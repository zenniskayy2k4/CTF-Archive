import struct
import hashlib
import binascii
import os
# Cần cài: pip install pycryptodome
from Crypto.Cipher import ARC4

def solve():
    filename = "ks_operations.kcf"
    identifier = b"ks2025" # Identifier CHÍNH XÁC
    
    if not os.path.exists(filename):
        print(f"[-] File {filename} not found.")
        return

    print(f"[+] Using Identifier: {identifier.decode()}")

    with open(filename, "rb") as f:
        header = f.read(128)
        
        # --- 1. TẠO MASTER KEY ---
        nonce = header[8:24]
        timestamp = header[24:32]
        file_count = header[32:34]
        salt = nonce + timestamp + file_count
        master_key = hashlib.sha256(salt + identifier).digest()
        
        # --- 2. GIẢI MÃ FAT ---
        fat_offset = struct.unpack('<Q', header[0x22:0x2A])[0]
        fat_size = struct.unpack('<I', header[0x2A:0x2E])[0]
        data_offset = struct.unpack('<Q', header[0x2E:0x36])[0]
        
        f.seek(fat_offset)
        cipher_fat = ARC4.new(master_key)
        fat_data = cipher_fat.decrypt(f.read(fat_size))
        
        entry_size = 96
        num_files = len(fat_data) // entry_size
        print(f"[+] FAT Decrypted. Files detected: {num_files}")
        
        out_dir = "extracted_flag"
        if not os.path.exists(out_dir): os.makedirs(out_dir)
        
        # --- 3. EXTRACT TỪNG FILE ---
        for index in range(num_files):
            entry = fat_data[index*entry_size : (index+1)*entry_size]
            
            # Parse Metadata (Dựa trên kết quả hex dump)
            # Byte 4-12: Offset (8 bytes)
            # Byte 12-16: Size (4 bytes)
            file_off = struct.unpack('<Q', entry[4:12])[0]
            file_sz = struct.unpack('<I', entry[12:16])[0]
            
            # --- 4. TẠO DERIVED KEY (THEO HINT 2) ---
            # Key = SHA256(Master + Index + Offset)[:16]
            idx_bytes = struct.pack('<I', index)
            off_bytes = struct.pack('<Q', file_off)
            
            derive_input = master_key + idx_bytes + off_bytes
            # Truncate xuống 16 bytes (128-bit)
            file_key = hashlib.sha256(derive_input).digest()[:16]
            
            # --- 5. GIẢI MÃ DATA ---
            f.seek(data_offset + file_off)
            
            # Đọc và giải mã
            # Vì file có thể lớn, đọc hết vào RAM nếu < 100MB
            if file_sz < 100 * 1024 * 1024:
                encrypted_data = f.read(file_sz)
                cipher_file = ARC4.new(file_key)
                plain_data = cipher_file.decrypt(encrypted_data)
                
                # Check Header để đặt đuôi file
                ext = ".bin"
                if plain_data.startswith(b'\x50\x4B'): ext = ".docx" # Zip/Office
                elif plain_data.startswith(b'\xD0\xCF'): ext = ".doc" # Legacy Office
                elif plain_data.startswith(b'\x89PNG'): ext = ".png"
                elif plain_data.startswith(b'%PDF'): ext = ".pdf"
                
                # Cố gắng tìm tên file trong phần còn lại của FAT Entry (từ byte 20)
                try:
                    meta_name = entry[20:].split(b'\0')[0].decode(errors='ignore')
                    if len(meta_name) > 1 and all(32<=ord(c)<=126 for c in meta_name):
                        safe_name = "".join([c for c in meta_name if c.isalnum() or c in "._-"])
                        fname = f"{safe_name}{ext}"
                    else:
                        fname = f"file_{index}{ext}"
                except:
                    fname = f"file_{index}{ext}"

                print(f"    -> Extracting: {fname} (Size: {file_sz})")
                with open(os.path.join(out_dir, fname), "wb") as w:
                    w.write(plain_data)
                    
            else:
                print(f"    [-] Skipping file {index} (Too big: {file_sz})")

    print(f"\n[SUCCESS] Check folder '{out_dir}' for 'file_0.docx'. The flag is inside!")

if __name__ == "__main__":
    solve()