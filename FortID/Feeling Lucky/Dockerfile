FROM debian:bookworm-slim AS build

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential ca-certificates file && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY chall.c tweetnacl.c tweetnacl.h compile.sh ./
RUN chmod +x ./compile.sh && ./compile.sh && file ./chall

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends socat ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -d /home/ctf -U -s /usr/sbin/nologin ctf
WORKDIR /home/ctf

COPY --from=build /build/chall /home/ctf/chall

COPY flag.txt /home/ctf/flag.txt

RUN chown -R root:root /home/ctf && \
    chmod 0555 /home/ctf && \
    chmod 0555 /home/ctf/chall && \
    chmod 0444 /home/ctf/flag.txt

USER ctf:ctf
EXPOSE 1337

ENTRYPOINT ["/usr/bin/socat", \
  "TCP-LISTEN:1337,reuseaddr,fork,keepalive", \
  "EXEC:/home/ctf/chall,stderr,setsid,sigint"]
