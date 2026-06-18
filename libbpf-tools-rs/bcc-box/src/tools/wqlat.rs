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
use chrono::Local;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct WqKey {
    pub wq_name: [u8; 24],
    pub slot: u64,
}
unsafe impl aya::Pod for WqKey {}

#[derive(Parser, Debug)]
#[command(name = "wqlat", about = "Summarize workqueue request latency as histograms.")]
pub struct Opts {
    #[arg(short = 'T', long, help = "Include timestamp on output")]
    pub timestamp: bool,

    #[arg(short = 'N', long, help = "Output in nanoseconds")]
    pub nanoseconds: bool,

    #[arg(short = 'W', long, help = "Print a histogram per work queue")]
    pub workqueues: bool,

    #[arg(short = 'w', long, help = "Print this workqueue only")]
    pub wqname: Option<String>,

    #[arg(help = "Output interval, in seconds", default_value = "99999999")]
    pub interval: u32,

    #[arg(help = "Number of outputs", default_value = "99999999")]
    pub count: u32,
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
        let mut low = ((1u128 << (i + 1)) >> 1) as u64;
        let high = ((1u128 << (i + 1)) - 1) as u64;
        if low == high {
            low = low.saturating_sub(1);
        }
        let val = vals[i];
        print!("{:>width$} -> {:<width$} : {:<8} |", low, high, val, width = width);
        print_stars(val, val_max, stars);
        println!("|");
    }
}

fn get_wq_name(name_bytes: &[u8; 24]) -> String {
    if let Some(pos) = name_bytes.iter().position(|&c| c == 0) {
        String::from_utf8_lossy(&name_bytes[..pos]).into_owned()
    } else {
        String::from_utf8_lossy(name_bytes).into_owned()
    }
}

pub async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut clap_args = vec!["wqlat".to_string()];
    clap_args.extend(args.iter().cloned());
    let opts = Opts::parse_from(clap_args);

    if let Some(ref wqname) = opts.wqname {
        if wqname.len() >= 24 {
            eprintln!("workqueue name len must be less than 24");
            std::process::exit(-1);
        }
    }

    let mut loader = EbpfLoader::new();

    let targ_workqueues: u8 = if opts.workqueues { 1 } else { 0 };
    let targ_ns: u8 = if opts.nanoseconds { 1 } else { 0 };
    let mut filter_wqname = [0u8; 24];
    if let Some(ref wqname) = opts.wqname {
        let bytes = wqname.as_bytes();
        let len = std::cmp::min(bytes.len(), 23);
        filter_wqname[..len].copy_from_slice(&bytes[..len]);
    }

    loader.set_global("WQLAT_TARG_WORKQUEUES", &targ_workqueues, true);
    loader.set_global("WQLAT_TARG_NS", &targ_ns, true);
    loader.set_global("WQLAT_FILTER_WQNAME", &filter_wqname, true);

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

    if let Some(ref btf_ref) = btf {
        let mut attached_enter = false;
        if let Some(enter) = bpf.program_mut("workqueue_queue_work_btf") {
            if let Ok(enter_btf) = <&mut BtfTracePoint>::try_from(enter) {
                if enter_btf.load("workqueue_queue_work", btf_ref).is_ok() && enter_btf.attach().is_ok() {
                    attached_enter = true;
                }
            }
        }
        if attached_enter {
            if let Some(exit) = bpf.program_mut("workqueue_execute_start_btf") {
                if let Ok(exit_btf) = <&mut BtfTracePoint>::try_from(exit) {
                    if exit_btf.load("workqueue_execute_start", btf_ref).is_ok() && exit_btf.attach().is_ok() {
                        use_btf = true;
                    }
                }
            }
        }
    }

    if !use_btf {
        let mut loaded_enter = false;
        if let Some(enter) = bpf.program_mut("workqueue_queue_work") {
            if let Ok(enter_prog) = <&mut RawTracePoint>::try_from(enter) {
                enter_prog.load()?;
                enter_prog.attach("workqueue_queue_work")?;
                loaded_enter = true;
            }
        }
        if !loaded_enter {
            return Err("program workqueue_queue_work not found or failed to load".into());
        }

        let mut loaded_exit = false;
        if let Some(exit) = bpf.program_mut("workqueue_execute_start") {
            if let Ok(exit_prog) = <&mut RawTracePoint>::try_from(exit) {
                exit_prog.load()?;
                exit_prog.attach("workqueue_execute_start")?;
                loaded_exit = true;
            }
        }
        if !loaded_exit {
            return Err("program workqueue_execute_start not found or failed to load".into());
        }
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("failed to listen for ctrl-c");
        r.store(false, Ordering::SeqCst);
    });

    println!("Tracing work queue request latency time... Hit Ctrl-C to end.");

    let interval_sec = opts.interval;
    let mut times = opts.count;

    let hists_map = bpf.take_map("WQLAT_HISTS").ok_or("map WQLAT_HISTS not found")?;
    let mut hists_map: HashMap<_, WqKey, u64> = HashMap::try_from(hists_map)?;

    while running.load(Ordering::SeqCst) && times > 0 {
        tokio::time::sleep(tokio::time::Duration::from_secs(interval_sec as u64)).await;

        if opts.timestamp {
            let ts = Local::now().format("%H:%M:%S").to_string();
            println!("{:<8}", ts);
        }

        let units = if opts.nanoseconds { "nsecs" } else { "usecs" };

        let mut keys = Vec::new();
        let mut entries = Vec::new();
        for item in hists_map.iter() {
            if let Ok((key, count)) = item {
                keys.push(key);
                entries.push((key, count));
            }
        }

        for key in &keys {
            let _ = hists_map.remove(key);
        }

        if !opts.workqueues {
            let mut global_slots = [0u32; 64];
            for (key, count) in &entries {
                let slot = key.slot as usize;
                if slot < 64 {
                    global_slots[slot] = global_slots[slot].saturating_add(*count as u32);
                }
            }

            println!();
            print_log2_hist(&global_slots, units);
        } else {
            let mut wq_hists = std::collections::BTreeMap::new();
            for (key, count) in &entries {
                let name = get_wq_name(&key.wq_name);
                let slots = wq_hists.entry(name).or_insert([0u32; 64]);
                let slot = key.slot as usize;
                if slot < 64 {
                    slots[slot] = slots[slot].saturating_add(*count as u32);
                }
            }

            for (name, slots) in &wq_hists {
                println!();
                println!("wqname = {}", name);
                print_log2_hist(slots, units);
            }
        }

        times -= 1;
    }

    Ok(())
}
