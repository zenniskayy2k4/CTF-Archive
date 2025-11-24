import struct

try:
    with open('hidden_strings', 'rb') as f:
        binary_data = f.read()
    print(f"[*] Successfully read {len(binary_data)} bytes from 'hidden_strings'.")
except FileNotFoundError:
    print("Error: File 'hidden_strings' not found.")
    exit()

# Dựa trên readelf, các địa chỉ trong segment .data có:
# File Offset = Virtual Address - 0x1000
DATA_SEGMENT_VADDR_START = 0x3d80
DATA_SEGMENT_OFFSET_DIFFERENCE = 0x1000

def va_to_offset(va):
    """Chuyển đổi địa chỉ ảo (PIE) thành file offset."""
    if va >= DATA_SEGMENT_VADDR_START:
        return va - DATA_SEGMENT_OFFSET_DIFFERENCE
    else:
        # Đối với các segment khác như .rodata, offset = va
        return va

# --- 1. Parse Bảng Cấu trúc Chuỗi ---
string_meta_table = []
meta_table_va = 0x4160 # Địa chỉ ảo của bảng meta
meta_table_offset = va_to_offset(meta_table_va)
print(f"[*] String meta table starts at VA 0x{meta_table_va:x}, File Offset 0x{meta_table_offset:x}")

i = 0
while True:
    current_offset = meta_table_offset + i * 24
    entry_data = binary_data[current_offset : current_offset + 24]
    if len(entry_data) < 24:
        break

    ptr_va = struct.unpack('<Q', entry_data[0:8])[0]
    length = struct.unpack('<Q', entry_data[8:16])[0]
    key = entry_data[16]

    if ptr_va == 0 and length == 0:
        break
        
    string_meta_table.append({
        'ptr_va': ptr_va, 'len': length, 'key': key
    })
    i += 1

print(f"[*] Parsed {len(string_meta_table)} entries from the string meta table.")

# --- 2. Hàm Giải mã Chuỗi ---
memo = {} 
def get_plain_string(index):
    if index in memo:
        return memo[index]
    
    meta = string_meta_table[index]
    
    # Áp dụng đúng phép chuyển đổi cho con trỏ data
    data_offset = va_to_offset(meta['ptr_va'])
    
    encrypted_data = binary_data[data_offset : data_offset + meta['len']]
    decrypted = bytearray(b ^ meta['key'] for b in encrypted_data)
    result = decrypted.decode('latin-1')
    memo[index] = result
    return result

# --- 3. Parse Bảng Chỉ số và Tái tạo Flag ---
index_pairs_va = 0x2020
index_pairs_offset = va_to_offset(index_pairs_va) # Bảng này nằm trong .rodata nên offset = va
print(f"[*] Index pairs table starts at VA 0x{index_pairs_va:x}, File Offset 0x{index_pairs_offset:x}")
middle_flag = ""

i = 0
while True:
    current_offset = index_pairs_offset + i * 2
    pair_bytes = binary_data[current_offset : current_offset + 2]
    if len(pair_bytes) < 2:
        break
        
    string_idx = pair_bytes[0]
    char_idx   = pair_bytes[1]
    
    if string_idx >= len(string_meta_table) or (string_idx == 0 and char_idx == 0 and i > 0):
        break
        
    plain_string = get_plain_string(string_idx)
    
    if char_idx >= len(plain_string):
        break
    
    middle_flag += plain_string[char_idx]
    i += 1
    
if middle_flag:
    final_flag = "ENO{" + middle_flag + "}"
    print(f"\n[*] Reconstructed flag: {final_flag}")
else:
    print("\n[-] Failed to reconstruct the flag.")