#!/usr/bin/env bash

# Stop on errors
set -e

# Determine directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Target architecture mappings
ARM64_TARGET="aarch64-unknown-linux-musl"
X86_64_TARGET="x86_64-unknown-linux-musl"

usage() {
    echo "Usage: $0 [target]"
    echo ""
    echo "Targets:"
    echo "  host      Build for the current host architecture (default)"
    echo "  arm64     Build statically-linked binary for ARM64 (AArch64) target"
    echo "  x86_64    Build statically-linked binary for x86_64 target"
    echo "  all       Build for both arm64 and x86_64 targets"
    echo "  clean     Clean build artifacts"
    echo ""
    exit 1
}

# Change to repo root to execute cargo commands consistently
cd "$REPO_ROOT"

# Ensure nightly toolchain and bpf target are installed (required for xtask build-ebpf)
ensure_toolchains() {
    echo "==> Checking BPF build prerequisites..."
    if ! rustup toolchain list | grep -q "nightly"; then
        echo "--> Installing nightly toolchain..."
        rustup toolchain install nightly
    fi

    # Ensure rust-src component is installed for nightly toolchain
    if ! rustup component list --toolchain nightly | grep -q "rust-src (installed)"; then
        echo "--> Adding rust-src component to nightly toolchain..."
        rustup component add rust-src --toolchain nightly
    fi
}

build_ebpf() {
    ensure_toolchains
    echo "==> Building eBPF bytecode (xtask build-ebpf)..."
    cargo xtask build-ebpf --release
}

build_userspace() {
    local target="$1"
    if [ "$target" = "host" ]; then
        echo "==> Building userspace for host..."
        cargo build --package bcc-box --release
    else
        echo "==> Adding target toolchain for $target..."
        rustup target add "$target"
        echo "==> Building userspace for $target..."
        cargo build --target "$target" --package bcc-box --release
        
        # Output info
        local binary_path="target/$target/release/bcc-box"
        if [ -f "$binary_path" ]; then
            echo "--> Binary built successfully: $binary_path"
            file "$binary_path"
        fi
    fi
}

clean() {
    echo "==> Cleaning cargo build artifacts..."
    cargo clean
    # Clean the copied ebpf resources
    rm -rf libbpf-tools-rs/bcc-box/resources/bcc-box-ebpf
    echo "--> Done."
}

# Default target is host if none provided
TARGET="${1:-host}"

case "$TARGET" in
    host)
        build_ebpf
        build_userspace "host"
        ;;
    arm64)
        build_ebpf
        build_userspace "$ARM64_TARGET"
        ;;
    x86_64)
        build_ebpf
        build_userspace "$X86_64_TARGET"
        ;;
    all)
        build_ebpf
        build_userspace "$ARM64_TARGET"
        build_userspace "$X86_64_TARGET"
        ;;
    clean)
        clean
        ;;
    -h|--help)
        usage
        ;;
    *)
        echo "Error: Unknown target '$TARGET'"
        usage
        ;;
esac
