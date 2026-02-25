import struct
import sys

def read_int(data, offset):
    # Đọc 4 bytes little-endian
    return struct.unpack('<I', data[offset:offset+4])[0]

def disassemble(filename):
    try:
        with open(filename, 'rb') as f:
            code = f.read()
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file {filename}")
        return

    pc = 0  # Program Counter
    length = len(code)

    print(f"{'OFFSET':<8} | {'OPCODE':<10} | {'PARAMS'}")
    print("-" * 40)

    while pc < length:
        opcode = code[pc]
        
        # Kết thúc
        if opcode == 0x00:
            print(f"0x{pc:04X}   | EXIT       |")
            break

        # Opcode 0x06: Jump if Zero (Logic hơi khác một chút trong code C)
        # C code: iVar3 = readInt; cVar1 = readByte; if (mem[iVar3]==0) pc += cVar1
        if opcode == 0x06:
            if pc + 6 > length: break
            addr = read_int(code, pc + 1)
            jump_offset = code[pc + 5]
            # Lưu ý: Code C có đoạn pc + 5 ở cuối loop, logic nhảy có thể là relative
            print(f"0x{pc:04X}   | JZ         | Check mem[0x{addr:X}] == 0, Offset: {jump_offset}")
            pc += 6 # Dựa theo code C (local_c = local_c + 5 nhưng index bắt đầu từ 0 nên nhảy 6 byte)
            continue

        # Opcode 0x05: Input
        if opcode == 0x05:
            if pc + 5 > length: break
            addr = read_int(code, pc + 1)
            print(f"0x{pc:04X}   | INPUT      | mem[0x{addr:X}]")
            pc += 5
            continue

        # Các Opcode toán học (1, 2, 3, 4)
        if pc + 6 > length: break
        addr = read_int(code, pc + 1)
        val = code[pc + 5]

        op_name = "UNKNOWN"
        if opcode == 0x01:
            op_name = "ADD" # mem[addr] += val
        elif opcode == 0x02:
            op_name = "SUB" # mem[addr] -= val
        elif opcode == 0x03:
            op_name = "MOD" # mem[addr] %= val
        elif opcode == 0x04:
            op_name = "MOV" # mem[addr] = val
        
        print(f"0x{pc:04X}   | {op_name:<10} | mem[0x{addr:X}], 0x{val:X} ({val})")
        pc += 6

if __name__ == "__main__":
    disassemble("code.pascal")