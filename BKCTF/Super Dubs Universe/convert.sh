#!/bin/bash

echo "[+] Extracting text from 200 pages..."
> full_code.txt

# Chạy ngược từ 200 về 1 vì level 200 là Page 1
for i in {200..1}; do
    # pdftotext là công cụ trong gói poppler-utils (có sẵn trên Linux)
    # Nó sẽ tự tìm header PDF trong file .jpg để trích xuất
    pdftotext "level$i.jpg" - >> full_code.txt
    echo -n "."
done

echo -e "\n[+] Done! Code saved to full_code.txt"