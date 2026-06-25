#!/bin/sh

set -e

# Restore Makefiles to their git state before making any modifications.
# Previous builds may have used sed -i to temporarily exclude tools
# (e.g. cmasnoop/cmatop/cmatrack on x86_64), and since the source
# directory is a Docker volume mount, those changes persist on the host.
cd /app/libbpf-tools
git checkout Makefile 2>/dev/null || true
cd /app/libbpf-tools-multi
git checkout Makefile 2>/dev/null || true

# Detect architecture and set ARCH correctly.
# Docker multi-platform builds use QEMU emulation; uname -m reports the
# guest architecture. The libbpf-tools Makefile's ARCH auto-detection handles
# x86_64→x86 and aarch64→arm64 correctly, but armv7l is not mapped to 'arm'.
UNAME_M=$(uname -m)
case "$UNAME_M" in
    x86_64)  ARCH=x86   ;;
    aarch64) ARCH=arm64  ;;
    armv7l)  ARCH=arm    ;;
    *)       ARCH=$UNAME_M ;;
esac

# For 32-bit ARM (armhf), add extra compiler flags to suppress warnings
# that -Werror in the upstream libbpf-tools Makefile would otherwise promote
# to errors (especially int/pointer cast and implicit int conversion issues
# that arise from 32-bit vs 64-bit differences).
if [ "$ARCH" = "arm" ]; then
    export EXTRA_CFLAGS="-Wno-sign-compare \
      -Wno-missing-field-initializers \
      -Wno-int-to-pointer-cast \
      -Wno-int-conversion \
      -Wno-error=format \
      -Wno-error=type-limits \
      -Wno-unknown-attributes \
      -Wno-error=unused-function \
      -Wno-error=format-truncation \
      -Werror=unused-variable"
fi

# build all tools in libbpf-tools
cd /app/libbpf-tools

# Patch gen.c to include libgen.h for basename()
if [ -f "bpftool/src/gen.c" ]; then
    sed -i '1i#include <libgen.h>' bpftool/src/gen.c
fi

# Clean previous build artifacts when BUILD_CLEAN=true (default for CI).
# When BUILD_CLEAN is unset or false, skip clean for incremental builds
# — make only recompiles files whose sources have changed.
if [ "$BUILD_CLEAN" = "true" ]; then
    echo "BUILD_CLEAN=true: running make clean for libbpf-tools..."
    make clean ARCH=$ARCH 2>/dev/null || true
else
    echo "Incremental build — skipping make clean for libbpf-tools."
fi

# Build tools with -k (keep going) so individual BPF compilation failures
# on a given architecture don't stop the rest of the build. Tools whose
# BPF programs fail to compile simply won't appear in the output.
# The multi-call Makefile auto-skips tools without skel.h headers.
# Run make twice: first pass handles a parallel build race where libbpf
# headers may not be fully installed when BPF compilation starts.
make ARCH=$ARCH -j`nproc` -k 2>&1 || true
make ARCH=$ARCH -j`nproc` -k 2>&1 || true

# Create output directories for stripped and debug versions
mkdir -p /app/out/stripped
mkdir -p /app/out/debug

# Copy and strip binaries
for tool in $(find . -maxdepth 1 -type f -executable); do
    # a temporary workaround for build script
    if [ "$tool" = "./build.sh" ]; then
        continue
    fi
    bn=$(basename "$tool")
    if ! file "$tool" | grep -q "ELF"; then
        echo "SKIP (not ELF): $bn"
        continue
    fi
    cp "$tool" "/app/out/debug/$bn"
    strip -s "/app/out/debug/$bn" -o "/app/out/stripped/$bn" 2>/dev/null || {
        echo "WARN: strip failed for $bn (wrong architecture?), skipping"
        rm -f "/app/out/debug/$bn"
    }
done

# Build the single multi-call binary
echo "Building libbpf-tools-multi binary..."
cd /app/libbpf-tools-multi
if [ "$BUILD_CLEAN" = "true" ]; then
    echo "BUILD_CLEAN=true: running make clean for multi-call binary..."
    make clean 2>/dev/null || true
else
    echo "Incremental build — skipping make clean for multi-call binary."
fi
make ARCH=$ARCH -j$(nproc)
cp libbpf-tools-box /app/out/debug/libbpf-tools-box
strip -s libbpf-tools-box -o /app/out/stripped/libbpf-tools-box 2>/dev/null || {
    echo "WARN: strip failed for libbpf-tools-box, copying unstripped"
    cp libbpf-tools-box /app/out/stripped/libbpf-tools-box
}

# Change ownership of the output files and build artifacts.
# Docker runs as root, so files created in mounted volumes end up
# owned by root on the host. Fix this so the host user can access
# and rebuild without permission errors.
if [ -n "$UID" ] && [ -n "$GID" ]; then
    chown -R "$UID:$GID" /app/out
    chown -R "$UID:$GID" /app/libbpf-tools/.output 2>/dev/null || true
    chown -R "$UID:$GID" /app/libbpf-tools-multi/.output 2>/dev/null || true
fi

