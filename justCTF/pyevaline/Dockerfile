FROM --platform=linux/amd64 python:3.13.5-bookworm

RUN useradd -m ctfplayer

COPY --chmod=755 app /home/ctfplayer/app
COPY --chmod=4755 runner /home/ctfplayer/runner
COPY --chmod=400 flag.txt /home/ctfplayer/flag.txt

WORKDIR /home/ctfplayer

USER ctfplayer
ENTRYPOINT ["/bin/sh"]
