FROM alpine:latest

COPY ./chall.c .
COPY ./flag.txt .

RUN apk add --no-cache build-base linux-headers socat nsjail coreutils
RUN cc -o chall chall.c

CMD ["nsjail", "-Ml", "--port", "1337", "--disable_clone_newuser", "--disable_clone_newuser", "--disable_clone_newpid", "--disable_clone_newnet", "--disable_clone_newns", "--disable_clone_newipc", "--disable_clone_newcgroup", "--disable_clone_newuts", "--", "./chall"]
