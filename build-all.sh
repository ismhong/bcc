#!/bin/sh

set -e

# ---------------------------------------------------------------------------
# build-all.sh — Multi-arch Docker cross-build for libbpf-tools
#
# Usage:
#   ./build-all.sh                    Incremental build (armhf, skip make clean)
#   ./build-all.sh --arch arm64       Build for a specific target arch
#   ./build-all.sh --clean            Full clean build (CI, cross-arch switch)
#   ./build-all.sh --rebuild          Force rebuild Docker images
#   ./build-all.sh --no-rebuild       Deprecated compat alias for auto-detect
#   ./build-all.sh -h, --help         Show this help message
#
# How Docker image caching works:
#   - The script checks if the bcc-builder image exists locally.
#     If it does, it skips "docker buildx build" entirely — just runs the container.
#   - The buildx builder is PERSISTENT (named "bcc-multiarch-builder"), not deleted
#     on exit. Its BuildKit cache survives across runs, so even when --rebuild is
#     needed, the "RUN apk add" layer hits the cache.
#   - For CI: on a fresh node the image doesn't exist → gets built once, then
#     cached by the Docker daemon. To optimize CI further, pre-push images to a
#     registry.
# ---------------------------------------------------------------------------

# --help / -h: show usage and exit
show_help() {
    cat <<'EOF'
Usage: ./build-all.sh [OPTION]

Multi-arch Docker cross-build for libbpf-tools (armhf).
Default target is armhf. Use --arch to build for a different target.

Options:
  -h, --help               Show this help message and exit
  --arch <arch>            Target architecture(s). Default: armhf.
                           Examples: --arch armhf, --arch "armhf x86_64"
  --clean                  Full clean build (make clean before compile).
                           Default: incremental build (only recompiles changed files).
  --rebuild                Force rebuild of Docker images, even if already cached locally
  --no-rebuild             (deprecated) No-op; auto-detect now skips images if present
  --upx                    Enable UPX compression of release binaries.
                           Default: UPX is skipped entirely; this flag is required
                           for compression regardless of --clean.
  --no-platform-check      Disable the Realtek-platform guard in compiled binaries.
                           By default, libbpf-tools-box only runs on Realtek RTD
                           platforms. This flag removes that restriction.

How it works:
  1. Builds Docker images for each target arch (auto-skipped if already present).
  2. Runs the build container for each arch via build.sh.
     By default, build artifacts are reused across runs — only changed files
     are recompiled. Pass --clean for a pristine rebuild.
  3. Strips executables. UPX compression is optional (pass --upx to enable).

Environment:
  The build container mounts the repo root as /app, so source changes are
  picked up on every run. Build artifacts persist in the mounted .output/
  directories for incremental builds.

Examples:
  ./build-all.sh                    Incremental build (armhf, fast)
  ./build-all.sh --clean            Full clean build (CI or release)
  ./build-all.sh --rebuild          Rebuild images after Dockerfile changes
EOF
    exit 0
}

# Ensure Ctrl+C reliably terminates the script.
# Without this trap, a non-interactive shell may continue past an interrupted
# child process, leaving the build running.
trap 'echo ""; echo "Interrupted — exiting."; exit 130' INT

FORCE_REBUILD=false

# Default: incremental build (skip make clean in container).
# Pass --clean for a pristine rebuild (CI or cross-arch switch).
BUILD_CLEAN=false

# Default target architecture. Override with --arch.
TARGET_ARCHS="armhf"

# Default: platform check included. Pass --no-platform-check to disable
# the Realtek-platform guard in the compiled binary.
NO_PLATFORM_CHECK=false

# Default: UPX compression off (only runs with --upx).
DO_UPX=false

# Handle flags (while loop so multiple flags can be combined)
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            show_help
            ;;
        --arch)
            shift
            if [ -z "$1" ]; then
                echo "Error: --arch requires an argument (e.g., --arch armhf)"
                exit 1
            fi
            TARGET_ARCHS="$1"
            echo "Build target(s): $TARGET_ARCHS"
            ;;
        --clean)
            BUILD_CLEAN=true
            echo "Clean build enabled — will run make clean inside container."
            ;;
        --rebuild)
            FORCE_REBUILD=true
            echo "Force rebuild enabled — will rebuild Docker image."
            ;;
        --no-rebuild)
            # Backward compat: this flag meant "don't rebuild", but auto-detect
            # already does that. Just proceed without rebuilding.
            echo "Note: --no-rebuild is deprecated. Auto-detect handles this automatically."
            ;;
        --upx)
            DO_UPX=true
            echo "UPX compression enabled."
            ;;
        --no-platform-check)
            NO_PLATFORM_CHECK=true
            echo "Platform check disabled — will compile without Realtek platform guard."
            ;;
        *)
            echo "Error: unknown option '$1'"
            show_help
            ;;
    esac
    shift
done

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

# Download UPX only when --upx is explicitly requested
if [ "$DO_UPX" = "true" ]; then
    InstallUpx
else
    echo "UPX compression not requested (use --upx to enable)."
fi

# ---------------------------------------------------------------------------
# Docker image build phase — only when needed
# ---------------------------------------------------------------------------

# Check which architectures need a new image
NEED_BUILD=false
for arch in $TARGET_ARCHS; do
    if ! docker image inspect "bcc-builder-$arch" >/dev/null 2>&1; then
        echo "Image bcc-builder-$arch not found locally — will build."
        NEED_BUILD=true
    fi
done

if [ "$FORCE_REBUILD" = true ] || [ "$NEED_BUILD" = true ]; then
    # Ensure QEMU binfmt interpreters are registered.
    # This allows Docker to run containers for different architectures.
    # The check avoids re-running the privileged container if already registered.
    if ! ls /proc/sys/fs/binfmt_misc/qemu-* >/dev/null 2>&1; then
        echo "Registering QEMU binfmt interpreters..."
        docker run --rm --privileged tonistiigi/binfmt --install all
    else
        echo "QEMU binfmt interpreters already registered."
    fi

    # Use a PERSISTENT builder — its BuildKit container and cache volume
    # survive across script runs, so layers stay cached.
    BUILDER_NAME="bcc-multiarch-builder"
    if docker buildx ls 2>/dev/null | grep -q "$BUILDER_NAME"; then
        echo "Reusing existing buildx builder '$BUILDER_NAME' (cache preserved)."
        docker buildx use "$BUILDER_NAME"
    else
        echo "Creating persistent buildx builder '$BUILDER_NAME'..."
        docker buildx create --use --name "$BUILDER_NAME" --driver-opt network=host
    fi

    for arch in $TARGET_ARCHS; do
        # Map architecture name to Docker platform
        case "$arch" in
            armhf) platform="linux/arm/v7" ;;
            *)     platform="linux/$arch" ;;
        esac

        echo "Building Docker image for $arch (platform: $platform)..."
        # BuildKit cache from the persistent builder means:
        #   - "FROM alpine:3.17"    → cached (layer already exists)
        #   - "RUN apk add ..."     → cached (layers from previous build)
        #   - "WORKDIR /app"        → cached
        # Only the first build (or --rebuild) actually runs anything.
        docker buildx build --load --platform "$platform" -t "bcc-builder-$arch" .
    done
else
    echo "Docker image already exists — skipping image build."
fi

# ---------------------------------------------------------------------------
# Build execution phase — run build containers for each target arch
# ---------------------------------------------------------------------------

for arch in $TARGET_ARCHS; do
    # Map architecture name to Docker platform
    case "$arch" in
        armhf) platform="linux/arm/v7" ;;
        *)     platform="linux/$arch" ;;
    esac

    # Create output directory for the architecture
    mkdir -p "libbpf-tools-out/$arch"

    echo "Running build container for $arch..."
    # Run the build container.
    # NOTE: build artifacts persist in .output/ (volume mount), so make
    #       only recompiles changed files unless --clean was passed.
    #       --init injects tini as PID 1 so Ctrl+C (SIGTERM) is properly
    #       forwarded to build.sh instead of being ignored by sh's PID 1.
    docker run --rm --init --platform "$platform" \
        -v "$(pwd):/app" \
        -v "$(pwd)/libbpf-tools-out/$arch:/app/out" \
        -e "UID=$(id -u)" \
        -e "GID=$(id -g)" \
        -e "BUILD_CLEAN=$BUILD_CLEAN" \
        -e "NO_PLATFORM_CHECK=$NO_PLATFORM_CHECK" \
        "bcc-builder-$arch"

    echo "Build for $arch complete. Verifying output..."
    file "libbpf-tools-out/$arch/stripped/bashreadline"

    # UPX compression: only runs when --upx is explicitly requested
    if [ "$DO_UPX" = "true" ]; then
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
    else
        echo "Incremental build — skipping UPX compression."
    fi

    echo "---------------------------------"
done

# ---------------------------------------------------------------------------
# Size comparison summary (only meaningful after a clean build with UPX)
# ---------------------------------------------------------------------------

if [ "$DO_UPX" = "true" ] && [ -f "./upx" ]; then
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
