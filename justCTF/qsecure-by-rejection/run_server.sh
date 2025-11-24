#!/usr/bin/env bash

docker build -t chall_qemu_secure -f ./Dockerfile .
docker run --pull=never --rm -p 127.0.0.1:1234:1234 -it chall_qemu_secure
