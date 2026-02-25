# Chuỗi alphabet được trích xuất từ GameUI.cs
text = "phqgiumeaylnofdxkrcvstzwb_{}ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

# Mảng index được trích xuất từ Secrets.cs
s = [
    24, 16, 18, 21, 13, 26, 29, 57, 1, 54,
    10, 14, 25, 8, 25, 6, 57, 61, 28, 0,
    35, 12, 45, 55, 18, 28, 39, 25, 0, 55,
    3, 57, 42, 41, 27
]

# Map index với chuỗi ký tự
flag = ""
for num in s:
    flag += text[num]

print("Flag:", flag)