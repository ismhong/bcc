mod tools;

fn print_help() {
    println!("bcc-box - Rust/Aya implementation of libbpf-tools");
    println!("\nUsage:");
    println!("  bcc-box <tool_name> [args]");
    println!("\nAvailable tools:");
    println!("  opensnoop - Trace open syscalls");
    println!("  execsnoop - Trace exec syscalls");
    println!("  softirqs  - Trace softirq event latency");
    println!("  hardirqs  - Trace hardirq event latency");
    println!("  wqlat     - Trace workqueue request latency");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<String> = std::env::args().collect();
    if args.is_empty() {
        print_help();
        return Ok(());
    }

    // Intercept and set global BTF file path
    if let Some(pos) = args.iter().position(|x| x == "--btf") {
        if pos + 1 < args.len() {
            let btf_path = args[pos + 1].clone();
            std::env::set_var("LIBBPF_VMLINUX_BTF", btf_path);
            args.remove(pos + 1);
            args.remove(pos);
        }
    }

    let program_name = std::path::Path::new(&args[0])
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    match program_name {
        "opensnoop" => {
            if let Err(e) = tools::opensnoop::run(&args[1..]).await {
                eprintln!("Error executing opensnoop: {}", e);
                std::process::exit(1);
            }
        }
        "execsnoop" => {
            if let Err(e) = tools::execsnoop::run(&args[1..]).await {
                eprintln!("Error executing execsnoop: {}", e);
                std::process::exit(1);
            }
        }
        "softirqs" => {
            if let Err(e) = tools::softirqs::run(&args[1..]).await {
                eprintln!("Error executing softirqs: {}", e);
                std::process::exit(1);
            }
        }
        "hardirqs" => {
            if let Err(e) = tools::hardirqs::run(&args[1..]).await {
                eprintln!("Error executing hardirqs: {}", e);
                std::process::exit(1);
            }
        }
        "wqlat" | "workqueue" => {
            if let Err(e) = tools::wqlat::run(&args[1..]).await {
                eprintln!("Error executing wqlat: {}", e);
                std::process::exit(1);
            }
        }
        _ => {
            if args.len() > 1 {
                match args[1].as_str() {
                    "opensnoop" => {
                        if let Err(e) = tools::opensnoop::run(&args[2..]).await {
                            eprintln!("Error executing opensnoop: {}", e);
                            std::process::exit(1);
                        }
                    }
                    "execsnoop" => {
                        if let Err(e) = tools::execsnoop::run(&args[2..]).await {
                            eprintln!("Error executing execsnoop: {}", e);
                            std::process::exit(1);
                        }
                    }
                    "softirqs" => {
                        if let Err(e) = tools::softirqs::run(&args[2..]).await {
                            eprintln!("Error executing softirqs: {}", e);
                            std::process::exit(1);
                        }
                    }
                    "hardirqs" => {
                        if let Err(e) = tools::hardirqs::run(&args[2..]).await {
                            eprintln!("Error executing hardirqs: {}", e);
                            std::process::exit(1);
                        }
                    }
                    "wqlat" | "workqueue" => {
                        if let Err(e) = tools::wqlat::run(&args[2..]).await {
                            eprintln!("Error executing wqlat: {}", e);
                            std::process::exit(1);
                        }
                    }
                    _ => {
                        print_help();
                    }
                }
            } else {
                print_help();
            }
        }
    }

    Ok(())
}
