#sudo docker run --rm -v "$(pwd):/out" yapster-build
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Install build tools
RUN apt-get update && \
    apt-get install -y \
        build-essential \
        gcc \
        libc6-dev \
        patchelf \
        file && \
    rm -rf /var/lib/apt/lists/*

# Working directory
WORKDIR /build

# Copy source
COPY main.c .

# Build
RUN gcc -Wall -g -o yapster main.c

# Bundle runtime loader + libc
RUN cp /lib/x86_64-linux-gnu/libc.so.6 ./libc.so.6 && \
    cp /lib64/ld-linux-x86-64.so.2 ./ld-linux-x86-64.so.2

# Patch binary
RUN patchelf \
    --set-interpreter ./ld-linux-x86-64.so.2 \
    --set-rpath . \
    yapster

# Export artifacts to mounted directory
CMD cp yapster libc.so.6 ld-linux-x86-64.so.2 /out