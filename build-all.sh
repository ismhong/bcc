#!/bin/sh

set -e

REBUILD_IMAGE=true
if [ "$1" = "--no-rebuild" ]; then
    echo "Skipping image rebuild."
    REBUILD_IMAGE=false
fi

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
    echo "---------------------------------"
done

echo "All builds complete!"
