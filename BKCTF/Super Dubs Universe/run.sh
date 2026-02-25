#!/bin/bash

# Bắt đầu từ level 1
current_file="level1.jpg"
level=1

echo "[+] Starting the deep dive..."

while true; do
    next_level=$((level + 1))
    next_file="level${next_level}.jpg"

    # Thử giải nén file hiện tại bằng 7z (7z rất mạnh trong việc bỏ qua junk data ở đầu)
    # -y: tự động chọn Yes cho mọi câu hỏi
    # > /dev/null: ẩn bớt log cho đỡ rối mắt
    7z x "$current_file" -y > /dev/null 2>&1

    # Kiểm tra xem file level tiếp theo có xuất hiện không
    if [ -f "$next_file" ]; then
        echo "[*] Extracted Level $level -> Found $next_file"
        current_file="$next_file"
        level=$next_level
    else
        echo "[!] No more level files found after Level $level."
        echo "[+] Checking for flag or interesting files..."
        ls -F
        break
    fi
done