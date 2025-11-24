#!/usr/bin/env bash

export FLAG="justCTF{fake_flag}"

docker run -p31337:31337 -e FLAG --rm -it blockchain
