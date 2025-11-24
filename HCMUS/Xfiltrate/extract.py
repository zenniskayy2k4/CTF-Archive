full_hex_string = ""
seen_ids = set()

print("Đang xử lý các DNS ID...")
with open("dns_ids.txt", "r") as f:
    for line in f:
        # Lấy ID từ dòng, ví dụ "0x1a2b"
        hex_id = line.strip()
        if hex_id not in seen_ids:
            seen_ids.add(hex_id)
            # Bỏ đi "0x" và nối vào chuỗi lớn
            full_hex_string += hex_id[2:]

with open("final_encrypted_data.txt", "w") as f_out:
    f_out.write(full_hex_string)

print(f"Hoàn tất! Dữ liệu mã hóa cuối cùng đã được lưu vào 'final_encrypted_data.txt'")
print(f"Tổng độ dài chuỗi hex: {len(full_hex_string)}")