FROM --platform=linux/amd64 debian:testing-slim
COPY --from=krallin/ubuntu-tini /usr/bin/tini /tini
ENTRYPOINT ["/tini", "--"]

RUN apt-get update && \
    apt-get -y install libudev-dev libssl-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /challenge
COPY solwanna.so ./

WORKDIR /app
COPY solwanna-server solwanna.so flag.txt ./

RUN chmod 755 /app/solwanna-server

EXPOSE 5001
USER nobody
CMD ["/app/solwanna-server"]
