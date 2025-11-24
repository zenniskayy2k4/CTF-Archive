FROM --platform=linux/amd64 fedora:24

COPY --chmod=4755 hello /usr/bin/hello
COPY --chmod=400 flag.txt /flag.txt

RUN useradd -m ctfplayer
WORKDIR /home/ctfplayer

USER ctfplayer
ENTRYPOINT ["/bin/sh"]
