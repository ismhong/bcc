use std::process::Command;
use std::fs;
use clap::Parser;
use anyhow::{Context, anyhow};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: SubCommand,
}

#[derive(Parser)]
enum SubCommand {
    BuildEbpf {
        #[arg(long)]
        release: bool,
    },
}

fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();
    match cli.command {
        SubCommand::BuildEbpf { release } => {
            build_ebpf(release)?;
        }
    }
    Ok(())
}

fn build_ebpf(release: bool) -> Result<(), anyhow::Error> {
    let mut args = vec![
        "+nightly",
        "build",
        "--manifest-path",
        "libbpf-tools-rs/bcc-box-ebpf/Cargo.toml",
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
    ];
    if release {
        args.push("--release");
    }

    let status = Command::new("cargo")
        .args(&args)
        .status()
        .context("Failed to run cargo build for ebpf")?;

    if !status.success() {
        return Err(anyhow!("cargo build for ebpf failed with status: {}", status));
    }

    // Copy the generated ELF to bcc-box/resources/ for userspace inclusion
    let profile = if release { "release" } else { "debug" };
    let src = format!("target/bpfel-unknown-none/{}/bcc-box-ebpf", profile);
    let dest_dir = "libbpf-tools-rs/bcc-box/resources";
    fs::create_dir_all(dest_dir).context("Failed to create resources directory")?;
    let dest = format!("{}/bcc-box-ebpf", dest_dir);
    fs::copy(&src, &dest).context(format!("Failed to copy {} to {}", src, dest))?;
    println!("Successfully built and copied ebpf program to {}", dest);

    Ok(())
}
