#!/bin/bash

for stream in smtp-tcp-stream/smtp-tcp-stream*.txt ; do
    password=$(sed -Ene '/^Content-ID/,/^--=/p' "$stream"|grep -Po 'Password: (.*)'|sed -Ee 's/Password: //')
    zip_filename=$(grep -Po 'filename.*\.zip' "$stream"|sed -Ee 's/.*"//')
    base64_file_data=$(sed -Ene '/^Content-ID/,/^--=/p' "$stream"|grep -Pv -e 'Content|--|Attached'|grep -P '\w+')

    echo "processing $stream"
    echo "password:$password"
    echo "zip_filename:$zip_filename"
    echo -n "$base64_file_data" | base64 -d > "$zip_filename"
    unzip -P "$password" "$zip_filename"
done