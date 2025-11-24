FROM python:3.13.7-slim-trixie

RUN pip install --no-cache-dir flask waitress protobuf

WORKDIR /app
COPY . .

USER nobody

ENV SIGNING_KEY="not_the_real_key"

CMD waitress-serve --listen "0.0.0.0:1337" --trusted-proxy '*' --trusted-proxy-headers 'x-forwarded-for x-forwarded-proto x-forwarded-port' --log-untrusted-proxy-headers --clear-untrusted-proxy-headers --threads 4 main:app
