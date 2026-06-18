use aya::{
    maps::{PerCpuArray, PerCpuValues},
    programs::{BtfTracePoint, RawTracePoint},
    EbpfLoader,
    Btf,
    Endianness,
};
use clap::Parser;
use bcc_box_common::{MAX_SLOTS, NR_SOFTIRQS};
use chrono::Local;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Hist {
    pub slots: [u32; MAX_SLOTS],
}
unsafe impl aya::Pod for Hist {}

#[derive(Parser, Debug)]
#[command(name = "softirqs", about = "Summarize soft irq event time as histograms.")]
pub struct Opts {
    #[arg(short = 'd', long, help = "Show distributions as histograms")]
    pub distributed: bool,

    #[arg(short = 'T', long, help = "Include timestamp on output")]
    pub timestamp: bool,

    #[arg(short = 'N', long, help = "Output in nanoseconds")]
    pub nanoseconds: bool,

    #[arg(short = 'C', long, help = "Show event counts with timing")]
    pub count: bool,

    #[arg(short = 'c', long, help = "Trace this cpu only", default_value = "-1")]
    pub cpu: i32,

    #[arg(help = "Print interval in seconds", default_value = "99999999")]
    pub interval: u32,

    #[arg(help = "Number of times to print", default_value = "99999999")]
    pub times: u32,
}

const EBPF: &[u8] = include_bytes!("../../resources/bcc-box-ebpf");

const VEC_NAMES: [&str; NR_SOFTIRQS] = [
    "hi",
    "timer",
    "net_tx",
    "net_rx",
    "block",
    "irq_poll",
    "tasklet",
    "sched",
    "hrtimer",
    "rcu",
];

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

pub async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut clap_args = vec!["softirqs".to_string()];
    clap_args.extend(args.iter().cloned());
    let opts = Opts::parse_from(clap_args);

    let mut loader = EbpfLoader::new();

    let targ_dist: u8 = if opts.distributed { 1 } else { 0 };
    let targ_ns: u8 = if opts.nanoseconds { 1 } else { 0 };
    let targ_cpu = opts.cpu;

    loader.set_global("SOFTIRQS_TARG_DIST", &targ_dist, true);
    loader.set_global("SOFTIRQS_TARG_NS", &targ_ns, true);
    loader.set_global("SOFTIRQS_TARG_CPU", &targ_cpu, true);

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
        if let Some(enter) = bpf.program_mut("softirq_entry_btf") {
            if let Ok(enter_btf) = <&mut BtfTracePoint>::try_from(enter) {
                if enter_btf.load("softirq_entry", btf_ref).is_ok() && enter_btf.attach().is_ok() {
                    attached_enter = true;
                }
            }
        }
        if attached_enter {
            if let Some(exit) = bpf.program_mut("softirq_exit_btf") {
                if let Ok(exit_btf) = <&mut BtfTracePoint>::try_from(exit) {
                    if exit_btf.load("softirq_exit", btf_ref).is_ok() && exit_btf.attach().is_ok() {
                        use_btf = true;
                    }
                }
            }
        }
    }

    // Fall back to raw tracepoints if BTF didn't succeed
    if !use_btf {
        let mut loaded_enter = false;
        if let Some(enter) = bpf.program_mut("softirq_entry") {
            if let Ok(enter_prog) = <&mut RawTracePoint>::try_from(enter) {
                enter_prog.load()?;
                enter_prog.attach("softirq_entry")?;
                loaded_enter = true;
            }
        }
        if !loaded_enter {
            return Err("program softirq_entry not found or failed to load".into());
        }

        let mut loaded_exit = false;
        if let Some(exit) = bpf.program_mut("softirq_exit") {
            if let Ok(exit_prog) = <&mut RawTracePoint>::try_from(exit) {
                exit_prog.load()?;
                exit_prog.attach("softirq_exit")?;
                loaded_exit = true;
            }
        }
        if !loaded_exit {
            return Err("program softirq_exit not found or failed to load".into());
        }
    }

    println!("Tracing soft irq event time... Hit Ctrl-C to end.");

    let interval_sec = opts.interval;
    let mut times = opts.times;

    let counts_map = bpf.take_map("SOFTIRQS_COUNTS").ok_or("map SOFTIRQS_COUNTS not found")?;
    let mut counts_map: PerCpuArray<_, u64> = PerCpuArray::try_from(counts_map)?;

    let time_map = bpf.take_map("SOFTIRQS_TIME").ok_or("map SOFTIRQS_TIME not found")?;
    let mut time_map: PerCpuArray<_, u64> = PerCpuArray::try_from(time_map)?;

    let hists_map = bpf.take_map("SOFTIRQS_HISTS").ok_or("map SOFTIRQS_HISTS not found")?;
    let mut hists_map: PerCpuArray<_, Hist> = PerCpuArray::try_from(hists_map)?;

    while times > 0 {
        let mut got_ctrl_c = false;
        tokio::select! {
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(interval_sec as u64)) => {}
            _ = tokio::signal::ctrl_c() => {
                got_ctrl_c = true;
            }
        }
        println!();

        if opts.timestamp {
            let ts = Local::now().format("%H:%M:%S").to_string();
            println!("{:<8}", ts);
        }

        let units = if opts.nanoseconds { "nsecs" } else { "usecs" };

        if !opts.distributed {
            println!(
                "{:<16} {:<11}  {:<11}",
                "SOFTIRQ",
                format!("TOTAL_{}", units),
                if opts.count { "TOTAL_count" } else { "" }
            );

            // Read counts and times, then clear them
            for vec in 0..NR_SOFTIRQS {
                let vec_u32 = vec as u32;
                let c_vals = counts_map.get(&vec_u32, 0)?;
                let t_vals = time_map.get(&vec_u32, 0)?;

                let count_sum: u64 = c_vals.iter().sum();
                let time_sum: u64 = t_vals.iter().sum();

                // Clear values in map for next interval
                let zero_counts = PerCpuValues::try_from(vec![0u64; c_vals.len()])?;
                counts_map.set(vec_u32, zero_counts, 0)?;

                let zero_time = PerCpuValues::try_from(vec![0u64; t_vals.len()])?;
                time_map.set(vec_u32, zero_time, 0)?;

                if count_sum > 0 {
                    if opts.count {
                        println!("{:<16} {:11}  {:11}", VEC_NAMES[vec], time_sum, count_sum);
                    } else {
                        println!("{:<16} {:11}", VEC_NAMES[vec], time_sum);
                    }
                }
            }
        } else {
            // Read histograms, sum across CPUs, clear, and print
            for vec in 0..NR_SOFTIRQS {
                let vec_u32 = vec as u32;
                let hists_vals = hists_map.get(&vec_u32, 0)?;

                let mut total_slots = [0u32; MAX_SLOTS];
                let mut has_data = false;
                for cpu_hist in hists_vals.iter() {
                    for slot in 0..MAX_SLOTS {
                        total_slots[slot] += cpu_hist.slots[slot];
                        if cpu_hist.slots[slot] > 0 {
                            has_data = true;
                        }
                    }
                }

                // Clear values in map for next interval
                let zero_hists = PerCpuValues::try_from(vec![Hist { slots: [0u32; MAX_SLOTS] }; hists_vals.len()])?;
                hists_map.set(vec_u32, zero_hists, 0)?;

                if has_data {
                    println!("softirq = {}", VEC_NAMES[vec]);
                    print_log2_hist(&total_slots, units);
                    println!();
                }
            }
        }

        times -= 1;
        if got_ctrl_c || times == 0 {
            break;
        }
    }

    Ok(())
}
