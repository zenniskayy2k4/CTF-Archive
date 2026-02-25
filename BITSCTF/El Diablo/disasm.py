import struct

# Opcode map reconstructed from FUN_0010627f (dispatch table)
# Notes:
# - All 16-bit immediates/addresses are little-endian: imm = lo | (hi<<8)
# - Some instructions are variable length (LOAD_STR, CMP_STR_IMM)
opcodes = {
    0x00: ("HALT", 0),

    0x01: ("LOAD_IMM16", 3),   # reg, lo, hi
    0x02: ("PRINT_HEX", 1),    # reg
    0x03: ("INT_TO_STR", 1),   # reg
    0x04: ("RAND", 1),         # reg

    0x10: ("JMP", 2),          # lo, hi
    0x11: ("JNZ", 2),          # lo, hi   (jump if Z == 0)
    0x12: ("JZ", 2),           # lo, hi   (jump if Z == 1)

    0x20: ("XOR", 3),          # dst, a, b
    0x21: ("ADD", 3),
    0x22: ("SUB", 3),
    0x23: ("MUL", 3),
    0x24: ("DIV", 3),
    0x25: ("INC", 1),          # reg
    0x26: ("DEC", 1),          # reg
    0x27: ("AND", 3),
    0x28: ("OR", 3),

    0x30: ("LOAD_STR", None),  # reg, len_lo, len_hi, <len bytes...>
    0x31: ("PRINT_STR", 1),    # reg
    0x32: ("STRCAT", 3),       # dst, r1, r2
    0x33: ("SYSTEM", 1),       # reg (string)
    0x34: ("ATOI", 1),         # reg (string -> int)

    0x40: ("CMP_REG", 2),      # r1, r2
    0x41: ("CMP_IMM16", 3),    # reg, lo, hi
    0x42: ("CMP_STR_IMM", None),  # reg, len_lo, len_hi, <len bytes...>
    0x43: ("IS_STR", 1),       # reg  (sets Z based on type)
    0x44: ("IS_INT", 1),       # reg

    0x50: ("NOP", 0),
    0x51: ("MOV", 2),          # dst, src

    0x60: ("LDR", 2),          # dst, addrReg
    0x61: ("STR", 2),          # src, addrReg
    0x62: ("MEMCPY", 3),       # dstAddrReg, srcAddrReg, lenReg

    0x70: ("PUSH", 1),         # reg
    0x71: ("POP", 1),          # reg
    0x72: ("RET", 0),
    0x73: ("CALL", 2),         # lo, hi

    # These two are installed at runtime in FUN_00103851 by writing into the dispatch table.
    0x82: ("GET_LICENSE_BYTE", 2),  # dstReg, idxReg
    0x84: ("PRINT_FLAG_CHAR", 1),   # reg
}

def _u16(lo, hi):
    return lo | (hi << 8)

def _fmt_bytes_as_str(b: bytes) -> str:
    # printable-ish rendering
    s = []
    for x in b:
        if 32 <= x <= 126 and x not in (0x5C, 0x22):  # avoid \ and "
            s.append(chr(x))
        elif x == 0x0A:
            s.append("\\n")
        elif x == 0x0D:
            s.append("\\r")
        elif x == 0x09:
            s.append("\\t")
        elif x == 0x22:
            s.append('\\"')
        elif x == 0x5C:
            s.append("\\\\")
        else:
            s.append(f"\\x{x:02x}")
    return '"' + "".join(s) + '"'

def disassemble_vm(filename):
    with open(filename, "rb") as f:
        bytecode = f.read()

    pc = 0
    print("=" * 80)
    print(f"{'PC':<6} | {'Hex':<30} | {'Instruction'}")
    print("=" * 80)

    while pc < len(bytecode):
        op = bytecode[pc]

        if op not in opcodes:
            print(f"{pc:04X}   | {op:02X}                           | UNKNOWN_OPCODE")
            pc += 1
            continue

        name, num_args = opcodes[op]

        # Variable-length: LOAD_STR / CMP_STR_IMM
        if op in (0x30, 0x42):
            if pc + 4 > len(bytecode):
                print(f"{pc:04X}   | {bytecode[pc:]:!r:<30} | {name} <truncated>")
                break

            reg = bytecode[pc + 1]
            lo = bytecode[pc + 2]
            hi = bytecode[pc + 3]
            n = _u16(lo, hi)

            start = pc + 4
            end = min(len(bytecode), start + n)
            blob = bytecode[start:end]

            hex_dump = " ".join(f"{b:02X}" for b in bytecode[pc:end])
            s = _fmt_bytes_as_str(blob)

            if op == 0x30:
                arg_str = f"R[{reg}] = {s}  (len={n})"
            else:
                arg_str = f"R[{reg}] == {s}  (len={n})"

            print(f"{pc:04X}   | {hex_dump:<30} | {name.ljust(16)} {arg_str}")
            pc = start + n
            continue

        # Fixed-length instructions
        args = []
        for i in range(num_args):
            idx = pc + 1 + i
            args.append(bytecode[idx] if idx < len(bytecode) else 0)

        ins_bytes = bytecode[pc:pc + 1 + num_args]
        hex_dump = " ".join(f"{b:02X}" for b in ins_bytes)

        arg_str = ""
        if op == 0x01:  # LOAD_IMM16
            reg, lo, hi = args
            imm = _u16(lo, hi)
            arg_str = f"R[{reg}] = 0x{imm:04X}"
        elif op in (0x10, 0x11, 0x12, 0x73):  # JMP/JNZ/JZ/CALL
            lo, hi = args
            addr = _u16(lo, hi)
            arg_str = f"0x{addr:04X}"
        elif op in (0x20, 0x21, 0x22, 0x23, 0x24, 0x27, 0x28):  # binops
            dst, a, b = args
            sym = {
                0x20: "^", 0x21: "+", 0x22: "-", 0x23: "*", 0x24: "/",
                0x27: "&", 0x28: "|",
            }[op]
            arg_str = f"R[{dst}] = R[{a}] {sym} R[{b}]"
        elif op in (0x25, 0x26, 0x02, 0x03, 0x04, 0x31, 0x33, 0x34, 0x43, 0x44, 0x70, 0x71, 0x84):
            reg = args[0]
            arg_str = f"R[{reg}]"
        elif op == 0x51:  # MOV
            dst, src = args
            arg_str = f"R[{dst}] = R[{src}]"
        elif op == 0x40:  # CMP_REG
            r1, r2 = args
            arg_str = f"R[{r1}] == R[{r2}]"
        elif op == 0x41:  # CMP_IMM16
            reg, lo, hi = args
            imm = _u16(lo, hi)
            arg_str = f"R[{reg}] == 0x{imm:04X}"
        elif op == 0x60:  # LDR
            dst, addr_reg = args
            arg_str = f"R[{dst}] = RAM[R[{addr_reg}]]"
        elif op == 0x61:  # STR
            src, addr_reg = args
            arg_str = f"RAM[R[{addr_reg}]] = R[{src}]"
        elif op == 0x62:  # MEMCPY
            dst_addr, src_addr, ln = args
            arg_str = f"RAM[R[{dst_addr}]..] = RAM[R[{src_addr}]..] (len=R[{ln}])"
        elif op == 0x82:  # GET_LICENSE_BYTE
            dst, idx = args
            arg_str = f"R[{dst}] = License[ R[{idx}] ]"
        else:
            arg_str = ", ".join(f"0x{a:02X}" for a in args)

        print(f"{pc:04X}   | {hex_dump:<30} | {name.ljust(16)} {arg_str}")
        pc += 1 + num_args

if __name__ == "__main__":
    disassemble_vm("decrypted_vm.bin")