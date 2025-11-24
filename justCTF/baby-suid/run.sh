#!/usr/bin/env bash

docker build -t chall_baby_suid -f ./Dockerfile .
docker run --pull=never --network none --memory 128m --cpus 0.5 --pids-limit 50 --ulimit nofile=64:64 --rm -it chall_baby_suid
