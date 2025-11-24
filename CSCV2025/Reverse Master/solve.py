# reconstruct_check.py
# Python reconstruction of checkSecondHalf + FUN_0011ad68
# - Provide a64_tbl_func(auVar6, imm) to emulate NEON table lookup
# - Use deterministic random by seeding random module if needed

import random
import struct

# ---------- helper utils ----------
def u64(x): return x & 0xFFFFFFFFFFFFFFFF
def bytes_to_u64_le(b):
    return int.from_bytes(b, 'little')
def u64_to_bytes_le(v):
    return v.to_bytes(8, 'little')

# Default naive a64_TBL emulation (VERY simple VTBL-like): uses auVar6's low 13 bytes as table
# This is only a placeholder — for real result you must implement correct table lookup or supply pb (table)
def default_a64_tbl(auVar6_bytes, imm):
    # auVar6_bytes: bytes-like (we expect at least 16 bytes as built in code)
    # imm: integer mask/imm value from call site (0x201000403020100)
    # We'll return a 64-bit integer built by mixing some bytes from auVar6_bytes.
    # NOTE: This is NOT the real NEON a64_TBL; replace it if you have a real table.
    src = auVar6_bytes
    # safe fallback: build u64 from src[0:8] xor rotated version
    a = int.from_bytes(src[0:8], 'little')
    b = int.from_bytes(src[8:16], 'little')
    res = u64((a ^ (b<<8) ^ 0x0102030405060708) & 0xFFFFFFFFFFFFFFFF)
    return res

# ---------- Implementation of FUN_0011ad68 ----------
def fun_0011ad68(param_bytes, a64_tbl_func=default_a64_tbl, verbose=False):
    """
    param_bytes: bytes-like object of length 16 (the user's second half to check)
    a64_tbl_func: function(auVar6_bytes, imm) -> 64-bit integer (emulate a64_TBL)
    Returns: integer 0 or 1 (matching original returns undefined4 but effectively boolean)
    """
    if len(param_bytes) != 16:
        if verbose: print("param length not 16 -> reject")
        return 0

    # pbVar11 = calloc(16,1)
    pb = bytearray(16)
    # initial state
    uVar13 = 0x1a2b
    bVar18 = 0
    local_90 = 0

    while True:
        if uVar13 < 0x7a8b:
            if uVar13 == 0x1a2b:
                # iVar9 = rand()%100 ; iVar10 = rand()%100
                iVar9 = random.randint(0, 2**31-1) % 100
                iVar10 = random.randint(0, 2**31-1) % 100
                uVar13 = 0xbecf
                if iVar9 * iVar9 + iVar10 * iVar10 <= (iVar10 + iVar9) * (iVar10 + iVar9):
                    uVar13 = 0x3c4d
            elif uVar13 == 0x3c4d:
                # require param_2 == 0x10; we assume it is (length 16)
                iVar9 = random.randint(0, 2**31-1) % 0x32 + 1
                iVar10 = random.randint(0, 2**31-1) % 0x32 + 1
                uVar13 = 0xbecf
                if iVar9 * iVar9 + iVar10 * iVar10 != (iVar10 + iVar9) * (iVar10 + iVar9) + iVar9 * iVar10 * -2 + 1:
                    uVar13 = 0x5e6f
            else:
                # uVar13 == 0x5e6f : the main generation branch
                # emulate puVar12 allocation and content
                # puVar12 5 bytes = { 0x7d, 0xe2, 0x14, 0xb8, 99 }
                b2 = 0x7d   # bVar2 = (byte)*puVar12
                b1 = 0xe2   # bVar1 = *((byte*)puVar12 + 1)
                b3 = 0x14
                b4 = 0xb8
                b5 = 99

                # local named bytes used in code
                bVar14 = 99
                bVar15 = 0x7d
                bVar17 = 0xe2
                bVar16 = 0x14
                bVar18 = 0xb8

                # compute pbVar11 entries per source
                # pbVar11[1] = (bVar17 ^ 0x6c) - 10 ^ bVar1;
                pb[1] = ((bVar17 ^ 0x6c) - 10) ^ b1 & 0xFF
                # *pbVar11 = (bVar15 ^ 0x2f) - 7 ^ bVar2;
                pb[0] = ((bVar15 ^ 0x2f) - 7) ^ b2 & 0xFF
                # pbVar11[2] = ((bVar16 | 1) ^ 0x95) - 0xd ^ bVar3 ^ 2;
                pb[2] = (((bVar16 | 1) ^ 0x95) - 0xd) ^ b3 ^ 2 & 0xFF
                # pbVar11[0xd] = (bVar18 ^ 8) - 0x2e ^ bVar4 ^ 0xd;
                pb[0xD] = (((bVar18 ^ 8) - 0x2e) ^ b4 ^ 0xd) & 0xFF
                # pbVar11[4] = (bVar14 ^ 0x74) - 0x13 ^ bVar5 ^ 4;
                pb[4] = (((bVar14 ^ 0x74) - 0x13) ^ b5 ^ 4) & 0xFF
                # pbVar11[0xf] = (bVar15 ^ 7) - 0x34 ^ bVar2 ^ 0xf;
                pb[0xF] = (((bVar15 ^ 7) - 0x34) ^ b2 ^ 0xF) & 0xFF
                # pbVar11[0x10] = 0  -> out of bounds (it was setting byte beyond 16), ignore
                # pbVar11[3] = ((bVar18 | 2) ^ 0x21) - 0x10 ^ bVar4;
                pb[3] = ((((bVar18 | 2) ^ 0x21) - 0x10) ^ b4) & 0xFF
                # pbVar11[0xe] = (bVar14 ^ 0x5a) - 0x31 ^ bVar5 ^ 0xe;
                pb[0xE] = (((bVar14 ^ 0x5A) - 0x31) ^ b5 ^ 0xE) & 0xFF

                # build auVar6 bytes according to code:
                # auVar6._0_5_ = uVar8  where uVar8 = *puVar12 (first 5 bytes as integer)
                # auVar6[8] = bVar2; [9]=bVar1; [10]=bVar3; [11]=bVar4; [12]=bVar5
                # fill 16 bytes total
                uVar8 = (b2 | (b1<<8) | (b3<<16) | (b4<<24) | (b5<<32))
                au = bytearray(16)
                # put little-endian uVar8 in au[0:8] (they wrote auVar6._0_5_ = uVar8)
                au[0:8] = uVar8.to_bytes(8, 'little')
                au[8] = b2
                au[9] = b1
                au[10] = b3
                au[11] = b4
                au[12] = b5
                # indices 13..15 left 0 (they set _13_3_ = 0)

                # call a64_TBL (user-supplied)
                uVar7 = a64_tbl_func(bytes(au), 0x201000403020100)

                # now compute bVar18 using uVar7 bytes
                # bVar18 = ((bVar18 | 7) ^ 0x4d) - 0x1f ^ 8 ^ (byte)(uVar7 >> 0x18)
                bVar18 = ((((bVar18 | 7) ^ 0x4d) - 0x1f) ^ 8 ^ ((uVar7 >> 0x18) & 0xFF)) & 0xFF

                # Compose bytes 5..? via CONCAT macros:
                # This constructs an 8-byte chunk and writes it into pbVar11+5 (so bytes 5..12)
                # We'll reconstruct each byte individually per code:
                # For clarity, compute the bytes extracted from uVar7:
                byte_u7 = [(uVar7 >> (8*i)) & 0xFF for i in range(8)]  # little endian order

                # mapping from the big CONCAT... expression in source:
                # pbVar11[5..12] = [ ... ]   we need to compute each idx explicitly:
                # Looking at CONCAT17(... CONCAT16(... CONCAT15(... CONCAT14(... CONCAT13(bVar18, CONCAT12((...byte>>0x10), CONCAT11(((bVar17|5)^0x47)-0x19 ^6 ^ (byte>>8), (bVar15 ^0x4c)-0x16 ^5 ^ (byte)uVar7)))))))
                # We'll compute step by step for clarity:
                # Let's compute bytes in order pb[5] .. pb[12]
                # Based on the nested CONCAT, mapping (from highest to lowest):
                # pb[5] = ((bVar16 | 0xb) ^ 0x53) - 0x2b ^ 0xc ^ (byte)(uVar7 >> 0x38)
                pb5 = ((((bVar16 | 0xb) ^ 0x53) - 0x2b) ^ 0xC ^ ((uVar7 >> 0x38) & 0xFF)) & 0xFF
                # pb[6] = (bVar17 ^ 0xe2) - 0x28 ^ 0xb ^ (byte)(uVar7 >> 0x30)
                pb6 = (((bVar17 ^ 0xe2) - 0x28) ^ 0xb ^ ((uVar7 >> 0x30) & 0xFF)) & 0xFF
                # pb[7] = (bVar15 ^ 0x17) - 0x25 ^ 10 ^ (byte)(uVar7 >> 0x28)
                pb7 = (((bVar15 ^ 0x17) - 0x25) ^ 10 ^ ((uVar7 >> 0x28) & 0xFF)) & 0xFF
                # pb[8] = ((bVar14 | 8) ^ 0x45) - 0x22 ^ 9 ^ (byte)(uVar7 >> 0x20)
                pb8 = ((((bVar14 | 8) ^ 0x45) - 0x22) ^ 9 ^ ((uVar7 >> 0x20) & 0xFF)) & 0xFF
                # next is CONCAT13(bVar18, CONCAT12(...)) means pb[9] = bVar18
                pb9 = bVar18 & 0xFF
                # pb[10] = (bVar16 ^ 0x28) - 0x1c ^ 7 ^ (byte)(uVar7 >> 0x10)
                pb10 = (((bVar16 ^ 0x28) - 0x1c) ^ 7 ^ ((uVar7 >> 0x10) & 0xFF)) & 0xFF
                # pb[11] = ((bVar17 | 5) ^ 0x47) - 0x19 ^ 6 ^ (byte)(uVar7 >> 8)
                pb11 = ((((bVar17 | 5) ^ 0x47) - 0x19) ^ 6 ^ ((uVar7 >> 8) & 0xFF)) & 0xFF
                # pb[12] = (bVar15 ^ 0x4c) - 0x16 ^ 5 ^ (byte)(uVar7)
                pb12 = (((bVar15 ^ 0x4c) - 0x16) ^ 5 ^ (uVar7 & 0xFF)) & 0xFF

                # write them into pb
                pb[5] = pb5
                pb[6] = pb6
                pb[7] = pb7
                pb[8] = pb8
                pb[9] = pb9
                pb[10] = pb10
                pb[11] = pb11
                pb[12] = pb12

                # After constructing pb[0..15], later they set uVar13 = 0xbecf or 0x7a8b by rand.
                iVar9 = random.randint(0, 2**31-1) % 100
                iVar10 = random.randint(0, 2**31-1) % 100
                uVar13 = 0xbecf
                if iVar9 * iVar9 + iVar10 * iVar10 <= (iVar10 + iVar9) * (iVar10 + iVar9):
                    uVar13 = 0x7a8b

        else:
            # uVar13 >= 0x7a8b
            if uVar13 < 0xbecf:
                if uVar13 == 0x7a8b:
                    # now compare pb with param_1
                    ok = True
                    for i in range(16):
                        if pb[i] != param_bytes[i]:
                            ok = False
                            break
                    if ok and bVar18 == param_bytes[8]:
                        # extra randomness gate:
                        iVar9 = random.randint(0, 2**31-1) % 100
                        iVar10 = random.randint(0, 2**31-1) % 100
                        if iVar9 * iVar9 + iVar10 * iVar10 <= (iVar10 + iVar9) * (iVar10 + iVar9):
                            uVar13 = 0x9cad
                            # goto LAB_0011b008
                    # else goto LAB_0011b004 -> uVar13 = 0xbecf
                    if uVar13 != 0x9cad:
                        uVar13 = 0xbecf
                else:
                    if uVar13 == 0x9cad:
                        local_90 = 1
                        uVar13 = 0xd1e2
                    else:
                        # other states goto LAB_... fallback
                        # they do some rand checks and possibly set uVar13 = 0xbecf
                        iVar9 = random.randint(0, 2**31-1) % 100
                        iVar10 = random.randint(0, 2**31-1) % 100
                        if iVar9 * iVar9 + iVar10 * iVar10 <= (iVar10 + iVar9) * (iVar10 + iVar9):
                            uVar13 = 0xbecf
            else:
                # uVar13 >= 0xbecf
                if uVar13 == 0xbecf:
                    local_90 = 0
                    uVar13 = 0xd1e2
                elif uVar13 == 0xd1e2:
                    return int(local_90)
                else:
                    # fallback random
                    iVar9 = random.randint(0, 2**31-1) % 100
                    iVar10 = random.randint(0, 2**31-1) % 100
                    if iVar9 * iVar9 + iVar10 * iVar10 <= (iVar10 + iVar9) * (iVar10 + iVar9):
                        uVar13 = 0xbecf

        # LAB_0011b008: rand() once then loop
        _ = random.randint(0, 2**31-1)
        # continue loop
    # end while

# ---------- Implementation of checkSecondHalf (high level) ----------
def check_second_half(get_string_callback, param1_bytes, a64_tbl_func=default_a64_tbl, verbose=False):
    """
    get_string_callback(param_3) -> returns user_string or None
    param1_bytes: bytes-like expected to be 16 bytes (the second half from Java side)
    Returns: True/False
    """
    # anti-debugger check placeholder
    # FUN_00119ca0() & 1 => debugger; we'll assume no debugger in typical run
    if False:
        # would log and return False
        return False

    # __s = Java callback to get input string (we simulate by passing param1 as bytes)
    s = get_string_callback()
    if s is None:
        # calls rand twice then return False
        _ = random.randint(0, 2**31-1)
        _ = random.randint(0, 2**31-1)
        return False

    s_len = len(s)
    # they do several rand-based branches before calling fun_0011ad68
    # but core: call FUN_0011ad68(__s, s_len & 0xffffffff)
    iVar3 = None
    # many random checks; we skip to branch where they call FUN_0011ad68
    iVar3 = fun_0011ad68(param1_bytes, a64_tbl_func=a64_tbl_func, verbose=verbose)

    # after function call, they do some random checks; if iVar3 != 0,
    # they run some rand gates which might result in True.
    if iVar3 != 0:
        iVar1 = random.randint(0, 2**31-1) % 100
        iVar2 = random.randint(0, 2**31-1) % 100
        if iVar1 * iVar1 + iVar2 * iVar2 <= (iVar2 + iVar1) * (iVar2 + iVar1):
            return True

    # final fallback: compute two randoms in 1..0x32 and check same arithmetic identity:
    iVar1 = random.randint(0, 2**31-1) % 0x32 + 1
    iVar2 = random.randint(0, 2**31-1) % 0x32 + 1
    return (iVar1 * iVar1 + iVar2 * iVar2) == ((iVar2 + iVar1) * (iVar2 + iVar1) + iVar1 * iVar2 * -2 + 1)

# ---------- Example usage ----------
if __name__ == "__main__":
    # deterministic seed for reproducible tests (remove for "real" random)
    random.seed(0)

    # Example param (16 bytes) - try with a candidate from your previous run
    # replace with candidate bytes you found (as ascii)
    candidate_hex = "8ea7cac794842440"  # example from your candidates (as ascii hex)
    try:
        param_bytes = bytes.fromhex(candidate_hex)
    except:
        # if candidate was ascii text, use ascii bytes
        param_bytes = candidate_hex.encode()[:16].ljust(16, b'\x00')

    # define get_string_callback (simulate Java returning the same string)
    def get_str():
        return b"dummy_input"

    result = check_second_half(get_str, param_bytes, a64_tbl_func=default_a64_tbl, verbose=True)
    print("check_second_half result:", result)
