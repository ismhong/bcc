FROM alpine:3.17

# Install build dependencies
RUN apk add --no-cache build-base clang llvm linux-headers git libelf-static argp-standalone zlib-static zstd-dev elfutils-dev

# Set the working directory
WORKDIR /app

# Run the build script
CMD ["/app/build.sh"]
