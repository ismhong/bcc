use aya::{
    maps::HashMap,
    programs::{BtfTracePoint, RawTracePoint},
    EbpfLoader,
    Btf,
    Endianness,
};
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use bcc_box_common::MAX_SLOTS;
use chrono::Local;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct IrqKey {
    pub name: [u8; 32],
    pub cpu: u32,
}
unsafe impl aya::Pod for IrqKey {}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct IrqInfo {
    pub count: u64,
    pub total_time: u64,
    pub max_time: u64,
    pub slots: [u32; MAX_SLOTS],
}
unsafe impl aya::Pod for IrqInfo {}

#[derive(Parser, Debug)]
#[command(name = "hardirqs", about = "Summarize hard irq event time as histograms.")]
pub struct Opts {
    #[arg(short = 'd', long, help = "Show distributions as histograms")]
    pub distributed: bool,

    #[arg(short = 'T', long, help = "Include timestamp on output")]
    pub timestamp: bool,

    #[arg(short = 'N', long, help = "Output in nanoseconds")]
    pub nanoseconds: bool,

    #[arg(short = 'C', long = "cpu-mode", help = "Display separately by CPU")]
    pub cpu_mode: bool,

    #[arg(short = 's', long = "cpu", help = "Trace this cpu only", default_value = "-1")]
    pub cpu: i32,

    #[arg(help = "Print interval in seconds", default_value = "99999999")]
    pub interval: u32,

    #[arg(help = "Number of times to print", default_value = "99999999")]
    pub times: u32,
}

const EBPF: &[u8] = include_bytes!("../../resources/bcc-box-ebpf");

fn print_stars(val: u32, val_max: u32, width: i32) {
    let val_max = if val_max == 0 { 1 } else { val_max };
    let num_stars = (std::cmp::min(val, val_max) as i64 * width as i64 / val_max as i64) as i32;
    let num_spaces = width - num_stars;
    let need_plus = val > val_max;

    for _ in 0..num_stars {
        print!("*");
    }
    for _ in 0..num_spaces {
        print!(" ");
    }
    if need_plus {
        print!("+");
    }
}

fn print_log2_hist(vals: &[u32], val_type: &str) {
    let stars_max = 40;
    let mut idx_max = -1;
    let mut val_max = 0;

    for (i, &val) in vals.iter().enumerate() {
        if val > 0 {
            idx_max = i as i32;
        }
        if val > val_max {
            val_max = val;
        }
    }

    if idx_max < 0 {
        return;
    }

    let idx_max = idx_max as usize;
    let pad_width_label = if idx_max <= 32 { 5 } else { 15 };
    let pad_width_val = if idx_max <= 32 { 19 } else { 29 };
    println!("{:>width_1$}{:<width_2$} : count    distribution", "", val_type, width_1 = pad_width_label, width_2 = pad_width_val);

    let stars = if idx_max <= 32 {
        stars_max
    } else {
        stars_max / 2
    };

    let width = if idx_max <= 32 { 10 } else { 20 };

    for i in 0..=idx_max {
        let mut low = (1u64 << (i + 1)) >> 1;
        let high = (1u64 << (i + 1)) - 1;
        if low == high {
            low = low.saturating_sub(1);
        }
        let val = vals[i];
        print!("{:>width$} -> {:<width$} : {:<8} |", low, high, val, width = width);
        print_stars(val, val_max, stars);
        println!("|");
    }
}

fn get_irq_name(name_bytes: &[u8; 32]) -> String {
    if let Some(pos) = name_bytes.iter().position(|&c| c == 0) {
        String::from_utf8_lossy(&name_bytes[..pos]).into_owned()
    } else {
        String::from_utf8_lossy(name_bytes).into_owned()
    }
}

pub async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut clap_args = vec!["hardirqs".to_string()];
    clap_args.extend(args.iter().cloned());
    let opts = Opts::parse_from(clap_args);

    let mut loader = EbpfLoader::new();

    let targ_dist: u8 = if opts.distributed { 1 } else { 0 };
    let targ_ns: u8 = if opts.nanoseconds { 1 } else { 0 };
    let targ_cpu = opts.cpu;
    let cpu_mode: u8 = if opts.cpu_mode { 1 } else { 0 };

    loader.set_global("HARDIRQS_TARG_DIST", &targ_dist, true);
    loader.set_global("HARDIRQS_TARG_NS", &targ_ns, true);
    loader.set_global("HARDIRQS_TARG_CPU", &targ_cpu, true);
    loader.set_global("HARDIRQS_CPU_MODE", &cpu_mode, true);

    let btf = if let Ok(btf_path) = std::env::var("LIBBPF_VMLINUX_BTF") {
        match Btf::parse_file(&btf_path, Endianness::default()) {
            Ok(b) => Some(b),
            Err(e) => {
                eprintln!("Warning: failed to parse custom BTF file {}: {}", btf_path, e);
                None
            }
        }
    } else {
        Btf::from_sys_fs().ok()
    };

    if let Some(ref b) = btf {
        loader.btf(Some(b));
    }

    let ebpf_data = EBPF.to_vec();
    let bpf = loader.load(&ebpf_data)?;
    let bpf: &'static mut aya::Bpf = Box::leak(Box::new(bpf));

    let mut use_btf = false;

    // Try to load and attach using BTF tracepoints first
    if let Some(ref btf_ref) = btf {
        let mut attached_enter = false;
        if let Some(enter) = bpf.program_mut("irq_handler_entry_btf") {
            if let Ok(enter_btf) = <&mut BtfTracePoint>::try_from(enter) {
                if enter_btf.load("irq_handler_entry", btf_ref).is_ok() && enter_btf.attach().is_ok() {
                    attached_enter = true;
                }
            }
        }
        if attached_enter {
            if let Some(exit) = bpf.program_mut("irq_handler_exit_btf") {
                if let Ok(exit_btf) = <&mut BtfTracePoint>::try_from(exit) {
                    if exit_btf.load("irq_handler_exit", btf_ref).is_ok() && exit_btf.attach().is_ok() {
                        use_btf = true;
                    }
                }
            }
        }
    }

    // Fall back to raw tracepoints if BTF didn't succeed
    if !use_btf {
        let mut loaded_enter = false;
        if let Some(enter) = bpf.program_mut("irq_handler_entry") {
            if let Ok(enter_prog) = <&mut RawTracePoint>::try_from(enter) {
                enter_prog.load()?;
                enter_prog.attach("irq_handler_entry")?;
                loaded_enter = true;
            }
        }
        if !loaded_enter {
            return Err("program irq_handler_entry not found or failed to load".into());
        }

        let mut loaded_exit = false;
        if let Some(exit) = bpf.program_mut("irq_handler_exit") {
            if let Ok(exit_prog) = <&mut RawTracePoint>::try_from(exit) {
                exit_prog.load()?;
                exit_prog.attach("irq_handler_exit")?;
                loaded_exit = true;
            }
        }
        if !loaded_exit {
            return Err("program irq_handler_exit not found or failed to load".into());
        }
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("failed to listen for ctrl-c");
        r.store(false, Ordering::SeqCst);
    });

    println!("Tracing hard irq event time... Hit Ctrl-C to end.");

    let interval_sec = opts.interval;
    let mut times = opts.times;

    let infos_map = bpf.take_map("HARDIRQS_INFOS").ok_or("map HARDIRQS_INFOS not found")?;
    let mut infos_map: HashMap<_, IrqKey, IrqInfo> = HashMap::try_from(infos_map)?;

    while running.load(Ordering::SeqCst) && times > 0 {
        tokio::time::sleep(tokio::time::Duration::from_secs(interval_sec as u64)).await;
        println!();

        if opts.timestamp {
            let ts = Local::now().format("%H:%M:%S").to_string();
            println!("{:<8}", ts);
        }

        let units = if opts.nanoseconds { "nsecs" } else { "usecs" };

        // Read all entries and clear map
        let mut keys = Vec::new();
        let mut entries = Vec::new();
        for item in infos_map.iter() {
            if let Ok((key, info)) = item {
                keys.push(key);
                entries.push((key, info));
            }
        }

        for key in &keys {
            let _ = infos_map.remove(key);
        }

        if !opts.distributed {
            if opts.cpu_mode {
                println!(
                    "{:<33} {:>11} {:>11} {:>9} {:>3}",
                    "HARDIRQ",
                    "TOTAL_count",
                    format!("TOTAL_{}", units),
                    format!("MAX_{}", units),
                    "CPU"
                );
            } else {
                println!(
                    "{:<33} {:>11} {:>11} {:>9}",
                    "HARDIRQ",
                    "TOTAL_count",
                    format!("TOTAL_{}", units),
                    format!("MAX_{}", units)
                );
            }

            // Sort by total_time descending
            entries.sort_by(|a, b| b.1.total_time.cmp(&a.1.total_time));

            for (key, info) in &entries {
                let irq_name = get_irq_name(&key.name);
                if opts.cpu_mode {
                    println!(
                        "{:<33} {:11} {:11} {:9} {:3}",
                        irq_name, info.count, info.total_time, info.max_time, key.cpu
                    );
                } else {
                    println!(
                        "{:<33} {:11} {:11} {:9}",
                        irq_name, info.count, info.total_time, info.max_time
                    );
                }
            }
        } else {
            // Sort by name, and then by cpu if cpu_mode is on
            entries.sort_by(|a, b| {
                let name_a = get_irq_name(&a.0.name);
                let name_b = get_irq_name(&b.0.name);
                let cmp_name = name_a.cmp(&name_b);
                if cmp_name == std::cmp::Ordering::Equal && opts.cpu_mode {
                    a.0.cpu.cmp(&b.0.cpu)
                } else {
                    cmp_name
                }
            });

            for (key, info) in &entries {
                let irq_name = get_irq_name(&key.name);
                if opts.cpu_mode {
                    print!("cpu = {} ", key.cpu);
                }
                println!("hardirq = {}", irq_name);
                print_log2_hist(&info.slots, units);
                println!();
            }
        }

        times -= 1;
    }

    Ok(())
}
