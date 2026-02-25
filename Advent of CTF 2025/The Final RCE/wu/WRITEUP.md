# The Final RCE — write‑up

This challenge is a heap exploitation task built around **GNU obstacks** + glibc 2.36 internals.

The provided solver (`solve.py`) uses this chain:

1. **Signed truncation** bug in “alloc” to move obstack pointers backwards.
2. **`obstack_free(NULL)` misuse** to create a reliable **use‑after‑free** (UAF).
3. **Heap leak** (obstack chunk pointers) and **libc leak** (unsorted bin fd).
4. **Largebin attack** to overwrite `_IO_list_all` with a controlled heap pointer.
5. **FSOP** at process exit to pivot into a ROP chain via `setcontext` and perform a direct `execve` syscall.

---

## 0) Environment / protections

- Binary: `chall` (amd64, PIE, NX, partial RELRO, no canary)
- Libc: `libc.so.6` (glibc 2.36, shipped with the challenge)
- Remote: `nc ctf.csd.lol 2024` with a PoW; `solve.py` uses `./redpwnpow`.

---

## 1) Vulnerabilities

### A. Signed 32‑bit truncation in allocation size

The program accepts a 64‑bit size, but updates the internal obstack pointer using only a **32‑bit signed** value.

Example: `0xFFFF_FFF0` is interpreted as `-0x10` for pointer arithmetic.

Impact:
- You can move `object_base` / `next_free` **backwards** inside the current obstack chunk.
- Subsequent “allocations” return pointers into **obstack metadata** (e.g. the chunk header).

### B. `obstack_free(NULL)` creates a UAF

If you `free()` an unallocated index, the pointer passed to `obstack_free` is `NULL`.

`obstack_free(obs, NULL)` frees the entire obstack chunk chain but the program keeps stale pointers in `chunks[]` and continues.

Impact:
- You get a stable **use‑after‑free** primitive on freed malloc chunks.
- This matches the author hint (“use a pointer that has already been freed?”).

### C. Info leak via `puts()`

`show(idx)` does `puts(chunks[idx])`.

Impact:
- Leaks bytes from an address until a `\0` byte.
- Useful to leak heap pointers and unsorted-bin libc pointers.

---

## 2) Phase 1 — Heap / obstack chunk leak

Goal: compute the current obstack malloc chunk addresses.

Technique used by `leak_obstack_chunk()`:

1. Create an **anchor** allocation at a known offset within the current obstack chunk.
2. Allocate with size `0xFFFF_FFF0` (interpreted as `-0x10`) to move `object_base` backwards.
3. Allocate a “0‑byte” object so its pointer lands on the obstack chunk header/fields.
4. `show()` leaks the chunk `limit` pointer.

From `limit`, we derive:

- `chunk_base = limit - 0xFE0` (this binary’s obstack “user size”)
- `chunk_header = chunk_base - 0x10`

These addresses are used later to forge malloc metadata and to place the final fake `FILE`.

---

## 3) Phase 2 — Libc leak via unsorted bin fd

Goal: leak a main_arena address.

Problem:
- If a topmost freed chunk consolidates into the top chunk, unsorted fd/bk pointers don’t remain in the user area.

Fix:
- The exploit **shrinks** the first malloc chunk “A” (originally `0xff0`) down to `0xf00` by overwriting its malloc header.
- It also forges a small **in‑use remainder** chunk after it, so freeing A does **not** consolidate into the top chunk.

Then:
- Trigger `obstack_free(NULL)` to free A to malloc.
- `show()` a stale pointer into A to leak unsorted `fd`.

Libc base:

- `libc_base = unsorted_fd - 0x1D3CC0` (glibc 2.36 `main_arena` unsorted fd offset).

---

## 4) Phase 3 — Largebin attack to overwrite `_IO_list_all`

This uses the second hint: “Which attack takes advantage of a freed chunk to write a heap address to a controlled address?” → **largebin attack**.

Target:
- `_IO_list_all` (global pointer used by glibc’s stdio cleanup/flush at exit).

High-level plan:

1. Make sure freed chunk A (`0xf00`) ends up in the **largebin**.
2. Corrupt A’s largebin size-sorted pointers via UAF:
   - Set `A->bk_nextsize = _IO_list_all - 0x20`.
3. Create another freed chunk “B” with size `0xe00` (same largebin index as `0xf00`) and free it to unsorted.
4. Allocate again so malloc processes unsorted B and inserts it into the largebin.

In the “insert smaller than smallest” largebin path, glibc performs writes equivalent to:

- `victim->bk_nextsize = fwd->fd->bk_nextsize`
- `fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim`

With `victim->bk_nextsize = _IO_list_all - 0x20`, the second write becomes:

- `*_IO_list_all = victim`

So `_IO_list_all` is overwritten to point at B (a heap address we control).

Stability detail:
- Before freeing the obstack chain again, the exploit sets B’s `struct _obstack_chunk.prev = NULL` so the obstack free walk does **not** free A again (avoids a double-free / heap corruption that would abort).

---

## 5) Phase 4 — FSOP at exit → `setcontext` pivot → `execve` syscall

At program exit, glibc calls `_IO_cleanup()` → `_IO_flush_all_lockp(0)`:

- It walks `for (fp = _IO_list_all; fp; fp = fp->_chain)`
- If the stream looks writable (`_IO_write_ptr > _IO_write_base` for narrow mode), it calls `_IO_OVERFLOW(fp, EOF)`.

Because we overwrote `_IO_list_all` to a heap address, we place a **fake `FILE`** structure at B’s header.

### Triggering the wide-file path

We point the fake file’s vtable at `_IO_wfile_jumps`, so `_IO_OVERFLOW` becomes `_IO_wfile_overflow`.

We ensure `_IO_wfile_overflow` calls `_IO_wdoallocbuf` by making wide buffer look uninitialized.

### Pivoting with `_IO_WDOALLOCATE` → `setcontext`

In glibc 2.36, `_IO_wdoallocbuf` does:

- `call [fp->_wide_data->_wide_vtable + 0x68]`  (the wide vtable `__doallocate` slot)

We set:

- `fp->_wide_data` → a controlled heap region
- `fp->_wide_data->_wide_vtable` → a fake wide vtable
- fake wide vtable `__doallocate` (offset `0x68`) → `setcontext`

### ROP chain

`setcontext` loads register state from memory and pivots the stack:

- `RSP = *(ctx + 0xA0)`
- return address is taken from `*(ctx + 0xA8)`

We lay out the fake `FILE` so:

- `FILE->_wide_data` is used as the new `RSP`
- `FILE->_freeres_list` is used as the first “RIP” (return address)

Then the ROP chain (stored in `wide_data`) performs:

- `execve("/bin/sh", ["/bin/sh","-c","cat flag* /flag 2>/dev/null",NULL], NULL)`

via a **direct syscall** (`rax=59; syscall`).

This avoids fragile glibc wrapper constraints and reliably prints the flag.

---

## 6) Solver

- Exploit script: `solve.py`
- Run locally: `python3 solve.py`
- Run remote: `python3 solve.py REMOTE=1`
- Optional custom command: `python3 solve.py REMOTE=1 CMD='id'`

---

## Notes

- The PoW is handled by `solve_pow()` with `./redpwnpow`.
- Offsets used match glibc 2.36 shipped with the challenge.
- The exploit uses UAF for both pointer corruption (largebin metadata) and for writing the final fake `FILE` into a freed heap chunk.
