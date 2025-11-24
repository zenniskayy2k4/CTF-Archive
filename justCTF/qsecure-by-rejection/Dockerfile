FROM ubuntu:25.04

RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y wget qemu-system-x86
RUN wget -O alpine.iso https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/alpine-standard-3.21.3-x86_64.iso

EXPOSE 1234/tcp
COPY ./flag.txt /flag.txt
CMD qemu-system-x86_64 \
    -machine pc \
    -m 386 \
    -smp 1 \
    -cdrom alpine.iso \
    -nographic \
    -monitor none \
    -s -S
