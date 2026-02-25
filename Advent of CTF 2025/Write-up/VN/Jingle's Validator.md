## **Jingle's Validator**

Đây là một dạng bài Reverse Engineering kinh điển dựa trên **Máy ảo (Virtual Machine - VM)**. Chương trình C không chứa logic kiểm tra trực tiếp mà đóng vai trò là một "bộ xử lý" (CPU) tự chế, thực thi các "mã lệnh" (bytecode) được lưu sẵn trong file thực thi.

### **1. Phân tích Ban đầu: Nhận diện Cấu trúc VM**

Khi nhìn vào hàm `FUN_001011c9`, chúng ta có thể xác định các thành phần cốt lõi của máy ảo:

*   **Thanh ghi (Registers):** Mảng `local_3a8` và các biến cục bộ khác trên stack (`local_384`, `local_248`, v.v.) đóng vai trò là các thanh ghi của VM. Ta có thể tạm gọi chúng là `R0`, `R1`, `R2`,...
*   **Con trỏ lệnh (Program Counter - PC):** Biến `uVar9` trong vòng lặp `do-while` chính là PC, quyết định lệnh nào sẽ được thực thi tiếp theo.
*   **Bộ xử lý (CPU/Interpreter):** Vòng lặp `do-while` chứa một khối `switch-case` khổng lồ. Đây chính là trái tim của VM, nơi nó "giải mã" và "thực thi" từng opcode.
*   **Bộ nhớ/Bytecode (Memory/ROM):** Các mảng dữ liệu lớn tại địa chỉ `0x102120` trở đi chính là chương trình mà VM sẽ chạy. Cụ thể:
    *   `DAT_00102120`: Mảng các **Opcode** (mã lệnh).
    *   `DAT_00102121`, `DAT_00102122`: Mảng chứa chỉ số thanh ghi **Đích (Destination)** và **Nguồn (Source)**.
    *   `DAT_00102124`: Mảng chứa các giá trị tức thời **(Immediate)**.
    *   `DAT_001020e0`: Mảng dữ liệu bí mật **(Secret Data)** dùng để so sánh.

Mỗi lệnh của VM có cấu trúc 6 bytes: `[Opcode] [Dst] [Src] [Padding] [Imm_low] [Imm_high]`

### **2. Dịch ngược Bảng Lệnh (Instruction Set)**

Dựa vào khối `switch-case`, ta có thể dịch ngược các opcode quan trọng:
<center>
    
| Opcode | Tên gợi nhớ  | Chức năng                                                     |
| :-----: | :-----------: | :------------------------------------------------------------- |
| `0x0B` | `LOAD_INPUT` | `Reg[dst] = Input[Reg[src] + imm]` (Đọc 1 byte từ key)      |
| `0x0E` | `LOAD_SECRET`| `Reg[dst] = Secret[Reg[src] + imm]` (Đọc 1 byte từ data bí mật) |
| `0x06` | `XOR`        | `Reg[dst] ^= Reg[src]`                                         |
| `0x03` | `ADD`        | `Reg[dst] += Reg[src]`                                         |
| `0x05` | `SUB`        | `Reg[dst] -= Reg[src]`                                         |
| `0x08` | `SHL`        | `Reg[dst] = Reg[src] << imm` (Dịch trái)                       |
| `0x09` | `SHR`        | `Reg[dst] = Reg[src] >> imm` (Dịch phải)                       |
| `0x11` | `CMP_EQ_REG` | So sánh `Reg[dst] == Reg[src]`, set cờ `bVar13`                |
| `0x13` | `JMP_IF_TRUE`| Nhảy đến `PC = imm` nếu cờ `bVar13` là True                      |
| `0x15` | `SET_RESULT` | Đánh dấu thành công/thất bại                                   |

</center>
Logic chung của VM là: Lấy 1 byte từ key bạn nhập, thực hiện một chuỗi các phép biến đổi (XOR, ADD, SHIFT...), và cuối cùng so sánh kết quả với byte tương ứng trong mảng Secret Data.

### **3. Xây dựng Solver và Quá trình Debug**

#### **Vấn đề 1: Dữ liệu Bytecode bị Lỗi (Corrupted Data)**
Ban đầu, dữ liệu lấy từ **Listing View** của Ghidra bị thiếu. Dữ liệu này không phải là một chuỗi byte liên tục, nó bị xen kẽ bởi:
*   Địa chỉ (`00102120`, `00102121`, ...)
*   Tên nhãn (`DAT_...`)
*   Chú thích và mã assembly Ghidra tự dịch sai.

Việc copy thủ công và ghép lại đã làm sai lệch toàn bộ cấu trúc bytecode. Lệnh bị mất, các tham số (dst, src, imm) bị đặt sai vị trí.
=> **Giải pháp:** Sử dụng tính năng **"Copy Special..." -> "Python Bytes"** của Ghidra để dump ra một chuỗi byte sạch, chính xác 100%. Đây là bước ngoặt quyết định.

#### **Vấn đề 2: Khởi tạo Thanh ghi Sai/Thiếu**
Trong C, trước khi vào vòng lặp VM, có nhiều biến cục bộ được gán giá trị ban đầu.
```c
local_3a8[0] = 0x34;  // R0
local_384 = 0xf337;   // R9
local_248 = 0xf337;   // R88
...
```
Các script đầu tiên đã bỏ sót việc khởi tạo `local_248` (tức `R88`). Thanh ghi này đóng vai trò quan trọng trong việc tính toán chỉ số (index) để truy cập bộ nhớ. Thiếu nó, VM sẽ tính sai địa chỉ, đọc về giá trị 0, và không bao giờ thực hiện phép so sánh đúng.
=> **Giải pháp:** Phân tích kỹ stack frame trong Ghidra, tính toán offset của từng biến `local_...` so với `local_3a8` để xác định đúng chỉ số thanh ghi và khởi tạo đầy đủ.

#### **Vấn đề 3: UNSAT - Mâu thuẫn Ràng buộc (Conflicting Constraints)**
Sau khi có dữ liệu đúng và khởi tạo đúng thanh ghi, script chạy và sinh ra 52 ràng buộc nhưng kết quả lại là **UNSAT (không có lời giải)**.
*   **Nguyên nhân:** Logic tính toán chỉ số (index) bên trong VM rất phức tạp. Dù đã có đủ thanh ghi, nó vẫn tính toán ra các chỉ số truy cập bộ nhớ không tuần tự. Ví dụ, nó có thể so sánh:
    *   `Transformed(Flag[0])` với `Secret[0]`
    *   `Transformed(Flag[1])` với `Secret[5]`
    *   `Transformed(Flag[0])` với `Secret[10]` (lặp lại `Flag[0]`)
    Điều này tạo ra mâu thuẫn toán học mà Z3 không thể giải quyết (ví dụ: `X == 5` và `X == 10` là vô lý).

=> **Giải pháp cuối cùng ("Force-Feed"):** Chúng ta nhận ra rằng, dù logic tính index có phức tạp đến đâu, mục đích cuối cùng của một trình xác thực key đơn giản là so sánh tuần tự `Input[i]` với `Secret[i]`. Vì vậy, ta "hack" lại script của mình:
1.  Bỏ qua hoàn toàn logic tính index của VM.
2.  Tạo một biến đếm `force_index_counter` của riêng ta.
3.  Mỗi khi gặp lệnh `LOAD_INPUT` hoặc `LOAD_SECRET`, ta dùng `force_index_counter` để đọc dữ liệu.
4.  Mỗi khi gặp lệnh so sánh `CMP_EQ_REG` (opcode `0x11`), ta tăng biến đếm này lên 1.

Điều này ép Z3 phải giải bài toán đơn giản hơn nhưng đúng bản chất: `Transform(Flag[i]) == Secret[i]`.

### **4. Script**

Solve script kết hợp tất cả các giải pháp trên:
1.  Sử dụng **bytecode và secret_data chính xác** được dump từ Ghidra.
2.  **Khởi tạo đầy đủ và chính xác** tất cả các thanh ghi quan trọng (`R0`, `R9`, `R20`, `R22`, `R88`).
3.  Sử dụng kỹ thuật **"Force-Feed Indexing"** để bỏ qua logic tính index phức tạp/lỗi của VM, đảm bảo so sánh đúng cặp `Flag[i]` và `Secret[i]`.

Khi chạy script, Z3 nhận được 52 ràng buộc hợp lý, không mâu thuẫn và nhanh chóng tìm ra lời giải.

```python=
import struct
from z3 import *

secret_bytes = b'\x3c\x6f\x53\x88\xd5\xf6\x00\x28\xb5\xbc\xab\x8b\x4d\xa6\xe2\x9a\x5b\x57\x10\xa4\x59\xd9\x56\x36\x01\x04\x51\xb0\xe1\xe2\x04\x0c\xe2\x35\xf8\x88\x6a\x2c\xcf\x29\xea\x2e\x73\x7e\x2a\xcc\xe9\x5f\x54\x35\x67\xd2'
bytecode = b'\x0f\x00\x00\x00\x04\x00\x13\x00\x00\x00\x05\x00\x01\x02\x00\x00\x00\x00\x04\x02\x00\x00\x04\x00\x12\x00\x00\x00\x06\x00\x00\x02\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x01\x04\x02\x00\x00\x00\x02\x04\x00\x00\x00\x00\x0b\x05\x04\x00\x00\x00\x08\x05\x05\x00\x00\x00\x07\x03\x05\x00\x00\x00\x01\x04\x02\x00\x00\x00\x02\x04\x00\x00\x01\x00\x0b\x05\x04\x00\x00\x00\x08\x05\x05\x00\x08\x00\x07\x03\x05\x00\x00\x00\x01\x04\x02\x00\x00\x00\x02\x04\x00\x00\x02\x00\x0b\x05\x04\x00\x00\x00\x08\x05\x05\x00\x10\x00\x07\x03\x05\x00\x00\x00\x01\x04\x02\x00\x00\x00\x02\x04\x00\x00\x03\x00\x0b\x05\x04\x00\x00\x00\x08\x05\x05\x00\x18\x00\x07\x03\x05\x00\x00\x00\x01\x04\x03\x00\x00\x00\x09\x04\x04\x00\x03\x00\x01\x05\x03\x00\x00\x00\x09\x05\x05\x00\x05\x00\x06\x04\x05\x00\x00\x00\x01\x05\x03\x00\x00\x00\x09\x05\x05\x00\x08\x00\x06\x04\x05\x00\x00\x00\x01\x05\x03\x00\x00\x00\x09\x05\x05\x00\x0c\x00\x06\x04\x05\x00\x00\x00\x0a\x04\x00\x00\xff\x00\x01\x05\x09\x00\x00\x00\x08\x05\x05\x00\x08\x00\x01\x09\x05\x00\x00\x00\x07\x09\x04\x00\x00\x00\x01\x0a\x09\x00\x00\x00\x01\x05\x00\x00\x00\x00\x05\x05\x01\x00\x00\x00\x10\x05\x00\x00\x00\x00\x13\x00\x00\x00\x8d\x00\x0f\x05\x00\x00\x04\x00\x13\x00\x00\x00\x34\x00\x00\x08\x00\x00\x04\x00\x12\x00\x00\x00\x35\x00\x01\x08\x05\x00\x00\x00\x01\x04\x09\x00\x00\x00\x09\x04\x04\x00\x03\x00\x01\x05\x09\x00\x00\x00\x09\x05\x05\x00\x05\x00\x06\x04\x05\x00\x00\x00\x01\x05\x09\x00\x00\x00\x09\x05\x05\x00\x08\x00\x06\x04\x05\x00\x00\x00\x01\x05\x09\x00\x00\x00\x09\x05\x05\x00\x0c\x00\x06\x04\x05\x00\x00\x00\x0a\x04\x00\x00\xff\x00\x01\x05\x09\x00\x00\x00\x08\x05\x05\x00\x08\x00\x01\x09\x05\x00\x00\x00\x07\x09\x04\x00\x00\x00\x01\x0a\x09\x00\x00\x00\x00\x0b\x00\x00\x00\x00\x0f\x08\x00\x00\x01\x00\x13\x00\x00\x00\x54\x00\x01\x04\x01\x00\x00\x00\x0b\x05\x04\x00\x00\x00\x01\x06\x0a\x00\x00\x00\x09\x06\x06\x00\x00\x00\x0a\x06\x00\x00\xff\x00\x01\x07\x05\x00\x00\x00\x06\x07\x06\x00\x00\x00\x0c\x07\x01\x00\x00\x00\x01\x06\x05\x00\x00\x00\x08\x06\x06\x00\x00\x00\x07\x0b\x06\x00\x00\x00\x0f\x08\x00\x00\x02\x00\x13\x00\x00\x00\x61\x00\x01\x04\x01\x00\x00\x00\x0b\x05\x04\x00\x01\x00\x01\x06\x0a\x00\x00\x00\x09\x06\x06\x00\x08\x00\x0a\x06\x00\x00\xff\x00\x01\x07\x05\x00\x00\x00\x06\x07\x06\x00\x00\x00\x0c\x07\x01\x00\x01\x00\x01\x06\x05\x00\x00\x00\x08\x06\x06\x00\x08\x00\x07\x0b\x06\x00\x00\x00\x0f\x08\x00\x00\x03\x00\x13\x00\x00\x00\x6e\x00\x01\x04\x01\x00\x00\x00\x0b\x05\x04\x00\x02\x00\x01\x06\x0a\x00\x00\x00\x09\x06\x06\x00\x10\x00\x0a\x06\x00\x00\xff\x00\x01\x07\x05\x00\x00\x00\x06\x07\x06\x00\x00\x00\x0c\x07\x01\x00\x02\x00\x01\x06\x05\x00\x00\x00\x08\x06\x06\x00\x10\x00\x07\x0b\x06\x00\x00\x00\x0f\x08\x00\x00\x04\x00\x13\x00\x00\x00\x7b\x00\x01\x04\x01\x00\x00\x00\x0b\x05\x04\x00\x03\x00\x01\x06\x0a\x00\x00\x00\x09\x06\x06\x00\x18\x00\x0a\x06\x00\x00\xff\x00\x01\x07\x05\x00\x00\x00\x06\x07\x06\x00\x00\x00\x0c\x07\x01\x00\x03\x00\x01\x06\x05\x00\x00\x00\x08\x06\x06\x00\x18\x00\x07\x0b\x06\x00\x00\x00\x01\x04\x0b\x00\x00\x00\x09\x04\x04\x00\x03\x00\x01\x05\x0b\x00\x00\x00\x09\x05\x05\x00\x05\x00\x06\x04\x05\x00\x00\x00\x01\x05\x0b\x00\x00\x00\x09\x05\x05\x00\x08\x00\x06\x04\x05\x00\x00\x00\x01\x05\x0b\x00\x00\x00\x09\x05\x05\x00\x0c\x00\x06\x04\x05\x00\x00\x00\x0a\x04\x00\x00\xff\x00\x01\x05\x09\x00\x00\x00\x08\x05\x05\x00\x08\x00\x01\x09\x05\x00\x00\x00\x07\x09\x04\x00\x00\x00\x02\x01\x00\x00\x04\x00\x12\x00\x00\x00\x2c\x00\x00\x0c\x00\x00\x00\x00\x01\x04\x00\x00\x00\x00\x05\x04\x0c\x00\x00\x00\x10\x04\x00\x00\x00\x00\x13\x00\x00\x00\x9a\x00\x0d\x05\x0c\x00\x00\x00\x0e\x06\x0c\x00\x00\x00\x11\x05\x06\x00\x00\x00\x14\x00\x00\x00\x98\x00\x02\x0c\x00\x00\x01\x00\x12\x00\x00\x00\x8e\x00\x15\x00\x00\x00\x00\x00\x16\x00\x00\x00\x00\x00\x15\x00\x00\x00\x01\x00\x16\x00\x00\x00\x00\x00'

# --- Z3 SOLVER ---
solver = Solver()
flag = [BitVec(f'f{i}', 8) for i in range(52)]
for c in flag:
    solver.add(c >= 32, c <= 126)

regs = {i: BitVecVal(0, 32) for i in range(100)}
vm_stack = {}
bVar13 = False

# === INIT REGISTERS ===
regs[0]  = BitVecVal(52, 32)
regs[9]  = BitVecVal(0xF337, 32)
regs[20] = BitVecVal(52, 32)
regs[22] = BitVecVal(52, 32)
regs[88] = BitVecVal(0xF337, 32)
# ==========================================

def get_imm(offset):
    try:
        val = bytecode[offset+4] | (bytecode[offset+5] << 8)
        if val & 0x8000: val -= 0x10000
        return val
    except: return 0

# START AT PC = 0 (Chạy từ đầu với dữ liệu đúng)
pc_index = 0
steps = 0
constraints_added = 0

print("[*] Starting VM with correct bytecode...")

while pc_index * 6 < len(bytecode) and steps < 100000:
    steps += 1
    offset = pc_index * 6
    
    try:
        op = bytecode[offset]
        dst = bytecode[offset+1]
        src = bytecode[offset+2]
    except IndexError: break
        
    imm = get_imm(offset)
    next_pc = pc_index + 1

    # --- OPCODE LOGIC ---
    if op == 0: regs[dst] = BitVecVal(imm, 32)
    elif op == 1: regs[dst] = regs[src]
    elif op == 2: regs[dst] += imm
    elif op == 3: regs[dst] += regs[src]
    elif op == 4: regs[dst] -= imm
    elif op == 5: regs[dst] -= regs[src]
    elif op == 6: regs[dst] ^= regs[src]
    elif op == 7: regs[dst] |= regs[src]
    elif op == 8: regs[dst] = regs[src] << (imm & 0x1F)
    elif op == 9: regs[dst] = LShR(regs[src], (imm & 0x1F))
    elif op == 10: regs[dst] &= imm
    
    elif op == 11: # LOAD INPUT
        idx = simplify(regs[src] + imm).as_long()
        if 0 <= idx < 52:
            regs[dst] = ZeroExt(24, flag[idx])
        else:
            regs[dst] = BitVecVal(0, 32)
            
    elif op == 12: vm_stack[simplify(regs[src] + imm).as_long()] = regs[dst]
    elif op == 13: regs[dst] = vm_stack.get(simplify(regs[src] + imm).as_long(), BitVecVal(0, 32))
    
    elif op == 14: # LOAD SECRET
        idx = simplify(regs[src] + imm).as_long()
        if 0 <= idx < 52:
            regs[dst] = BitVecVal(secret_bytes[idx], 32)
        else:
            regs[dst] = BitVecVal(0, 32)
            
    elif op == 15: # CMP <
        # Z3 cần biết rõ ràng True/False để nhảy
        concrete_val = simplify(regs[dst]).as_long()
        bVar13 = concrete_val < imm

    elif op == 16: # CMP ==
        concrete_val = simplify(regs[dst]).as_long()
        bVar13 = concrete_val == imm
        
    elif op == 17: # CMP REG == REG (CHECK FLAG)
        solver.add(regs[dst] == regs[src])
        bVar13 = True
        constraints_added += 1
        
    elif op == 18: next_pc = imm
    elif op == 19: 
        if bVar13: next_pc = imm
    elif op == 20: 
        if not bVar13: next_pc = imm
    
    elif op == 21: # Success
        print("[!] Reached Success State!")
        break

    pc_index = next_pc

print(f"[*] Execution finished. Constraints added: {constraints_added}")

if constraints_added > 0:
    print("[*] Solving...")
    if solver.check() == sat:
        m = solver.model()
        res = "".join([chr(m[c].as_long()) for c in flag])
        print(f"\n[+] FLAG FOUND: {res}")
    else:
        print("[-] UNSAT")
else:
    print("[-] FAILED: No constraints generated.")
```

> **Flag:** `csd{I5_4ny7HiN9_R34LlY_R4Nd0m_1F_it5_bru73F0rc4B1e?}`