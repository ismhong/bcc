#!/bin/sh

set -e

# build all tools in libbpf-tools
cd /app/libbpf-tools

# Patch gen.c to include libgen.h for basename()
if [ -f "bpftool/src/gen.c" ]; then
    sed -i '1i#include <libgen.h>' bpftool/src/gen.c
fi

make -j`nproc`

# Create output directories for stripped and debug versions
mkdir -p /app/out/stripped
mkdir -p /app/out/debug

# Copy and strip binaries
for tool in $(find . -maxdepth 1 -type f -executable); do
    # a temporary workaround for build script
    if [ "$tool" = "./build.sh" ]; then
        continue
    fi
    cp "$tool" "/app/out/debug/$(basename "$tool")"
    strip -s "/app/out/debug/$(basename "$tool")" -o "/app/out/stripped/$(basename "$tool")"
done

# Build the single multi-call binary
echo "Building libbpf-tools-multi binary..."
cd /app/libbpf-tools-multi
make -j$(nproc)
cp libbpf-tools-box /app/out/debug/libbpf-tools-box
strip -s libbpf-tools-box -o /app/out/stripped/libbpf-tools-box

# Change ownership of the output files
if [ -n "$UID" ] && [ -n "$GID" ]; then
    chown -R "$UID:$GID" /app/out
fi

