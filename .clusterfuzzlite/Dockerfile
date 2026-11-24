# ClusterFuzzLite builds the fuzz targets in fuzz/ in this image.
FROM gcr.io/oss-fuzz-base/base-builder-rust:v1@sha256:d345218878c78feed410f0ad57268617a368912b224f844bbdb71c54c0b9955a
# The image's nightly is older than the server's minimum Rust version.
ENV RUSTUP_TOOLCHAIN=nightly-2026-09-23
RUN rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal
COPY . $SRC/mcp
WORKDIR $SRC/mcp
COPY .clusterfuzzlite/build.sh $SRC/
