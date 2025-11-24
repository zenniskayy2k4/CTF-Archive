# Dữ liệu mã hóa lấy từ Ghidra
dir1 = [0xc3, 0xd5, 0xc4, 0xc2, 0xd4, 0xd7, 0xc5, 0xd3, 0x98, 0xd2, 0xda, 0xda]
dir2 = [0xfd, 0xf3, 0xe4, 0xf8, 0xf3, 0xfa, 0xf4, 0xf7, 0xe5, 0xf3, 0x98, 0xd2, 0xda, 0xda]
dir3 = [0xf5, 0xc4, 0xd3, 0xd7, 0xc2, 0xd3, 0xf0, 0xdf, 0xda, 0xd3, 0xe1]

# Brute-force key từ 0 đến 255
for key in range(256):
    pdir1 = "".join([chr((b & 0xFF) ^ key) for b in dir1])
    pdir2 = "".join([chr((b & 0xFF) ^ key) for b in dir2])
    pdir3 = "".join([chr((b & 0xFF) ^ key) for b in dir3])
    
    # Giả định rằng tên DLL và tên hàm phải là các ký tự in được (printable)
    if pdir1.isprintable() and pdir2.isprintable():
        print(f"[*] Trying Key: {key} (0x{key:02x})")
        print(f"  -> pdir1: {pdir1}")
        print(f"  -> pdir2: {pdir2}")
        print(f"  -> pdir3: {pdir3}")
        # Thường thì tên hàm sẽ bắt đầu bằng chữ cái
        if pdir1[0].isalpha() and pdir2[0].isalpha():
            print("\n[+] Found plausible key!\n")