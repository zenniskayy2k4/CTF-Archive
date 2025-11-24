#!/usr/bin/env python3
from pwn import *

# Cài đặt pwntools để không in ra quá nhiều thông tin gỡ lỗi
context.log_level = 'info'

# Thông tin kết nối
HOST = 'bytecode-bonanza-basics.chal.crewc.tf'
PORT = 1337

# Kết nối đến server với SSL/TLS
io = remote(HOST, PORT, ssl=True)

# --- Payload 1: Hàm trừ (a - b) ---
# Stack ban đầu: [a, b] (b ở trên cùng)
# UNARY_NEGATIVE (0x0b) -> stack: [a, -b]
# BINARY_ADD (0x17) -> stack: [a + (-b)]
# Đây là logic a + (-b). Lần thử đầu tiên của chúng ta có thể đã sai ở một payload khác.
# Hãy tin tưởng vào logic đơn giản nhất.
subtract_hex = "0b001700" 
io.recvuntil(b"Enter a function which subtracts two numbers: ")
io.sendline(subtract_hex.encode())
info(f"Sent subtract payload: {subtract_hex}")

# --- Payload 2: Hàm hằng số 1337 ---
# POP_TOP (0x01) để xóa đối số đầu vào.
# LOAD_CONST (0x64) với chỉ số 0. Giả định server đã chuẩn bị hằng số 1337 cho chúng ta.
constant_hex = "01006400"
io.recvuntil(b"Enter a function which always returns 1337: ")
io.sendline(constant_hex.encode())
info(f"Sent constant payload: {constant_hex}")

# --- Payload 3: Hàm nhân (a * b) ---
# Sử dụng opcode trực tiếp: BINARY_MULTIPLY (0x14)
multiply_hex = "1400"
io.recvuntil(b"Enter a function which multiplies two positive integers: ")
io.sendline(multiply_hex.encode())
info(f"Sent multiply payload: {multiply_hex}")

# --- Nhận cờ ---
# Nếu tất cả payload đều đúng, server sẽ gửi lại cờ
flag = io.recvall().decode()
info(f"Flag: {flag.strip()}")

# Đóng kết nối
io.close()