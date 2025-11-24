FROM embe221ed/otter_template:justctf2025@sha256:e0768a12564a1f76fd1c525be983f298b88705896c9fb95e1a52646d420f4f8d


ADD ./sources/framework/chall /work/framework/chall
ADD ./sources/framework/src/main.rs /work/framework/src/

# build the challenge contracts
WORKDIR /work/framework/chall
RUN sui move build

WORKDIR /work/framework

# build the framework
RUN touch src/main.rs
RUN cargo build --locked --release

RUN echo "max_connections = 1000" >> /etc/postgresql/16/main/postgresql.conf

CMD [ "./run.sh" ]
