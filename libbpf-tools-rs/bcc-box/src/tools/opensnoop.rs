use aya::{
    programs::KProbe,
    EbpfLoader,
    maps::AsyncPerfEventArray,
    util::online_cpus,
    Btf,
    Endianness,
};
use bytes::BytesMut;
use clap::Parser;
use bcc_box_common::OpensnoopEvent;
use chrono::Local;

#[derive(Parser, Debug)]
#[command(name = "opensnoop", about = "Trace open syscalls")]
pub struct Opts {
    #[arg(short = 'p', long, help = "Trace this PID only")]
    pub pid: Option<u32>,

    #[arg(short = 't', long, help = "Trace this TGID only")]
    pub tgid: Option<u32>,

    #[arg(short = 'u', long, help = "Trace this UID only")]
    pub uid: Option<u32>,

    #[arg(short = 'x', long, help = "Trace only failed open syscalls")]
    pub failed: bool,
}

const EBPF: &[u8] = include_bytes!("../../resources/bcc-box-ebpf");

pub async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut clap_args = vec!["opensnoop".to_string()];
    clap_args.extend(args.iter().cloned());
    let opts = Opts::parse_from(clap_args);

    let mut loader = EbpfLoader::new();

    let targ_pid = opts.pid.unwrap_or(0);
    let targ_tgid = opts.tgid.unwrap_or(0);
    let targ_uid = opts.uid.unwrap_or(0xFFFFFFFF);
    let targ_failed: u8 = if opts.failed { 1 } else { 0 };

    loader.set_global("OPENSNOOP_TARG_PID", &targ_pid, true);
    loader.set_global("OPENSNOOP_TARG_TGID", &targ_tgid, true);
    loader.set_global("OPENSNOOP_TARG_UID", &targ_uid, true);
    loader.set_global("OPENSNOOP_TARG_FAILED", &targ_failed, true);

    let btf = if let Ok(btf_path) = std::env::var("LIBBPF_VMLINUX_BTF") {
        match Btf::parse_file(&btf_path, Endianness::default()) {
            Ok(b) => Some(b),
            Err(e) => {
                eprintln!("Warning: failed to parse custom BTF file {}: {}", btf_path, e);
                None
            }
        }
    } else {
        None
    };

    if let Some(ref b) = btf {
        loader.btf(Some(b));
    }

    let ebpf_data = EBPF.to_vec();
    let bpf = loader.load(&ebpf_data)?;
    let bpf: &'static mut aya::Bpf = Box::leak(Box::new(bpf));

    let program_enter: &mut KProbe = bpf
        .program_mut("opensnoop_enter")
        .ok_or("program opensnoop_enter not found")?
        .try_into()?;
    program_enter.load()?;
    let _ = program_enter.attach("__arm64_sys_openat", 0);
    let _ = program_enter.attach("__arm64_compat_sys_openat", 0);

    let program_exit: &mut KProbe = bpf
        .program_mut("opensnoop_exit")
        .ok_or("program opensnoop_exit not found")?
        .try_into()?;
    program_exit.load()?;
    let _ = program_exit.attach("__arm64_sys_openat", 0);
    let _ = program_exit.attach("__arm64_compat_sys_openat", 0);

    println!(
        "{: <8} {: <7} {: <16} {: <4} {: <3} {}",
        "TIME", "PID", "COMM", "FD", "ERR", "PATH"
    );

    let perf_array = AsyncPerfEventArray::try_from(
        bpf.map_mut("EVENTS").ok_or("map EVENTS not found")?
    )?;
    let perf_array: &'static mut AsyncPerfEventArray<_> = Box::leak(Box::new(perf_array));



    let cpus = online_cpus().map_err(|(s, e)| format!("{}: {}", s, e))?;
    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, None)?;
        tokio::spawn(async move {
            let mut buffers = vec![BytesMut::with_capacity(1024); 10];
            loop {
                match buf.read_events(&mut buffers).await {
                    Ok(events) => {
                        for i in 0..events.read {
                            let buf = &buffers[i];
                            if buf.len() < std::mem::size_of::<OpensnoopEvent>() {
                                continue;
                            }
                            let event = unsafe { &*(buf.as_ptr() as *const OpensnoopEvent) };

                            let comm = std::str::from_utf8(&event.comm)
                                .unwrap_or("")
                                .trim_end_matches('\0');
                            let fname = std::str::from_utf8(&event.fname)
                                .unwrap_or("")
                                .trim_end_matches('\0');

                            let ts = Local::now().format("%H:%M:%S").to_string();

                            let (fd_str, err_str) = if event.ret >= 0 {
                                (event.ret.to_string(), "0".to_string())
                            } else {
                                ("-1".to_string(), (-event.ret).to_string())
                            };

                            println!(
                                "{: <8} {: <7} {: <16} {: <4} {: <3} {}",
                                ts, event.pid, comm, fd_str, err_str, fname
                            );
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }

    tokio::signal::ctrl_c().await.expect("failed to listen for ctrl-c");

    Ok(())
}
