# ClusterFuzzLite builds the fuzz targets in fuzz/ in this image.
FROM gcr.io/oss-fuzz-base/base-builder-rust:v1@sha256:8d2315aeda612bc4176bf20057a72db2a7f61cdf4a8699829c147ab5af02d234
# The image's nightly is older than the server's minimum Rust version.
ENV RUSTUP_TOOLCHAIN=nightly-2026-09-23
RUN rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal
COPY . $SRC/mcp
WORKDIR $SRC/mcp
COPY .clusterfuzzlite/build.sh $SRC/
