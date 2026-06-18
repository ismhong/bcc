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
use bcc_box_common::ExecsnoopEvent;

#[derive(Parser, Debug)]
#[command(name = "execsnoop", about = "Trace exec syscalls")]
pub struct Opts {
    #[arg(short = 'u', long, help = "Trace this UID only")]
    pub uid: Option<u32>,

    #[arg(short = 'x', long, help = "Include failed exec syscalls")]
    pub failed: bool,

    #[arg(short = 'm', long, default_value = "20", help = "Max number of arguments to show")]
    pub max_args: u32,
}

const EBPF: &[u8] = include_bytes!("../../resources/bcc-box-ebpf");

pub async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut clap_args = vec!["execsnoop".to_string()];
    clap_args.extend(args.iter().cloned());
    let opts = Opts::parse_from(clap_args);

    let mut loader = EbpfLoader::new();

    let targ_uid = opts.uid.unwrap_or(0xFFFFFFFF);
    let max_args = opts.max_args;
    let ignore_failed: u8 = if opts.failed { 0 } else { 1 };

    loader.set_global("EXECSNOOP_TARG_UID", &targ_uid, true);
    loader.set_global("EXECSNOOP_MAX_ARGS", &max_args, true);
    loader.set_global("EXECSNOOP_IGNORE_FAILED", &ignore_failed, true);

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
        .program_mut("execve_enter")
        .ok_or("program execve_enter not found")?
        .try_into()?;
    program_enter.load()?;

    if cfg!(target_arch = "aarch64") {
        let _ = program_enter.attach("__arm64_sys_execve", 0);
        let _ = program_enter.attach("__arm64_compat_sys_execve", 0);
    } else {
        program_enter.attach("__x64_sys_execve", 0)?;
    }

    let program_exit: &mut KProbe = bpf
        .program_mut("execve_exit")
        .ok_or("program execve_exit not found")?
        .try_into()?;
    program_exit.load()?;
    
    if cfg!(target_arch = "aarch64") {
        let _ = program_exit.attach("__arm64_sys_execve", 0);
        let _ = program_exit.attach("__arm64_compat_sys_execve", 0);
    } else {
        program_exit.attach("__x64_sys_execve", 0)?;
    }

    println!(
        "{: <16} {: <7} {: <7} {: <4} {}",
        "PCOMM", "PID", "PPID", "RET", "ARGS"
    );

    let perf_array = AsyncPerfEventArray::try_from(
        bpf.map_mut("EXEC_EVENTS_OUTPUT").ok_or("map EXEC_EVENTS_OUTPUT not found")?
    )?;
    let perf_array: &'static mut AsyncPerfEventArray<_> = Box::leak(Box::new(perf_array));



    let cpus = online_cpus().map_err(|(s, e)| format!("{}: {}", s, e))?;
    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, None)?;
        tokio::spawn(async move {
            let mut buffers = vec![BytesMut::with_capacity(8192); 10];
            loop {
                match buf.read_events(&mut buffers).await {
                    Ok(events) => {
                        for i in 0..events.read {
                            let buf = &buffers[i];
                            if buf.len() < std::mem::size_of::<ExecsnoopEvent>() {
                                continue;
                            }
                            let event = unsafe { &*(buf.as_ptr() as *const ExecsnoopEvent) };

                            let comm = std::str::from_utf8(&event.comm)
                                .unwrap_or("")
                                .trim_end_matches('\0');

                             // Parse arguments separated by \0
                            let mut args_list = Vec::new();
                            let mut start = 0;
                            let mut count = 0;
                            let limit_size = event.args_size as usize;
                            while start < limit_size && count < event.args_count {
                                let mut end = start;
                                while end < limit_size && event.args[end] != 0 {
                                    end += 1;
                                }
                                if end > start {
                                    if let Ok(arg) = std::str::from_utf8(&event.args[start..end]) {
                                        args_list.push(arg);
                                    }
                                } else {
                                    args_list.push("");
                                }
                                start = end + 1;
                                count += 1;
                            }

                            println!(
                                "{: <16} {: <7} {: <7} {: <4} {}",
                                comm, event.pid, event.ppid, event.retval, args_list.join(" ")
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
