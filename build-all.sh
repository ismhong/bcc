#!/bin/sh

set -e

REBUILD_IMAGE=true
if [ "$1" = "--no-rebuild" ]; then
    echo "Skipping image rebuild."
    REBUILD_IMAGE=false
fi

#
# UPX compression support — download and cache upx binary for the host arch.
#
InstallUpx() {
    HOST_ARCH=$(uname -m)
    UPX_ARCH=""
    if [ "$HOST_ARCH" = "x86_64" ]; then
        UPX_ARCH="amd64"
    elif [ "$HOST_ARCH" = "aarch64" ]; then
        UPX_ARCH="arm64"
    else
        echo "Info: upx compression is not supported on '$HOST_ARCH'"
        return
    fi

    if [ -f "./upx" ]; then
        echo "UPX already downloaded."
        return
    fi

    UPX_VERSION="5.0.2"
    UPX_URL="https://github.com/upx/upx/releases/download/v${UPX_VERSION}/upx-${UPX_VERSION}-${UPX_ARCH}_linux.tar.xz"
    echo "Downloading UPX v${UPX_VERSION} (${UPX_ARCH})..."
    wget "${UPX_URL}" -O upx.tar.xz
    tar -xf upx.tar.xz
    mv "upx-${UPX_VERSION}-${UPX_ARCH}_linux/upx" ./upx
    rm upx.tar.xz
    rm -rf "upx-${UPX_VERSION}-${UPX_ARCH}_linux"
    chmod +x ./upx
}

InstallUpx

if [ "$REBUILD_IMAGE" = true ]; then
    # Ensure QEMU binfmt interpreters are registered.
    # This allows Docker to run containers for different architectures.
    docker run --rm --privileged tonistiigi/binfmt --install all

    # Create a new builder with host networking to solve DNS issues
    docker buildx create --use --name temp-builder --driver-opt network=host

    # Trap to ensure builder is cleaned up on exit
    trap 'docker buildx rm temp-builder' EXIT
fi

TARGET_ARCHS="arm64 x86_64"

for arch in $TARGET_ARCHS; do
    # Map architecture name to Docker platform
    case "$arch" in
        arm64)  platform="linux/arm64" ;;
        x86_64) platform="linux/amd64" ;;
        *)      platform="linux/$arch" ;;
    esac

    if [ "$REBUILD_IMAGE" = true ]; then
        echo "Building for $arch (platform: $platform)..."
        # Use docker buildx to build for different platforms
        docker buildx build --load --platform "$platform" -t "bcc-builder-$arch" .
    fi

    # Create output directory for the architecture
    mkdir -p "libbpf-tools-out/$arch"

    echo "Running build container for $arch..."
    # Run the build container
    docker run --rm --platform "$platform" \
        -v "$(pwd):/app" \
        -v "$(pwd)/libbpf-tools-out/$arch:/app/out" \
        -e "UID=$(id -u)" \
        -e "GID=$(id -g)" \
        "bcc-builder-$arch"

    echo "Build for $arch complete. Verifying output..."
    file "libbpf-tools-out/$arch/stripped/bashreadline"

    # Compress stripped executables with UPX (if available)
    UPX_DIR="libbpf-tools-out/$arch/upx"
    mkdir -p "$UPX_DIR"
    if [ -f "./upx" ]; then
        echo "Compressing with UPX for $arch..."
        for exe in "libbpf-tools-out/$arch/stripped/"*; do
            if [ -f "$exe" ] && [ -x "$exe" ]; then
                bn=$(basename "$exe")
                cp "$exe" "$UPX_DIR/$bn"
                ./upx --best "$UPX_DIR/$bn" 2>/dev/null || {
                    echo "  UPX: $bn (skipped)"
                    rm -f "$UPX_DIR/$bn"
                }
            fi
        done
        echo "UPX compression complete."
    else
        echo "UPX not available, skipping compression."
    fi

    echo "---------------------------------"
done

# Print size comparison summary
if [ -f "./upx" ]; then
    echo ""
    echo "=== Size comparison (stripped vs UPX) ==="
    for arch in $TARGET_ARCHS; do
        upx_dir="libbpf-tools-out/$arch/upx"
        stripped_dir="libbpf-tools-out/$arch/stripped"
        if [ -d "$upx_dir" ] && [ -d "$stripped_dir" ]; then
            echo "--- $arch ---"
            for exe in "$stripped_dir/"*; do
                bn=$(basename "$exe")
                upx_file="$upx_dir/$bn"
                if [ -f "$upx_file" ]; then
                    before=$(stat -c%s "$exe" 2>/dev/null || stat -f%z "$exe" 2>/dev/null)
                    after=$(stat -c%s "$upx_file" 2>/dev/null || stat -f%z "$upx_file" 2>/dev/null)
                    if [ "$before" -gt 0 ] 2>/dev/null; then
                        pct=$(( (before - after) * 100 / before ))
                        printf "  %-24s %s → %s (%d%% saved)\n" "$bn" \
                            "$(numfmt --to=iec $before 2>/dev/null || echo ${before}B)" \
                            "$(numfmt --to=iec $after 2>/dev/null || echo ${after}B)" \
                            "$pct"
                    fi
                fi
            done
        fi
    done
fi

echo ""
echo "All builds complete!"
