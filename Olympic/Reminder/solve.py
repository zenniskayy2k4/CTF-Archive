from Crypto.Cipher import AES

def solve():
    answers = [95, 123, 73, 109, 82, 83, 101, 100, 114, 65, 105, 102, 97, 101, 110, 111]
    
    print("Su dung bo dap an da duoc tinh toan truoc do:")
    print(answers)
    
    # 2. TẠO KHÓA: Lấy byte cuối của mỗi đáp án (answer % 256)
    key = bytes([n % 256 for n in answers])
    
    # 3. IV được hardcode trong chương trình
    iv_hex = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    iv = bytes.fromhex(iv_hex)

    print(f"\nSu dung khoa 16-byte: {key.hex()}")
    print(f"Su dung IV:             {iv.hex()}")

    try:
        with open('out.bin', 'rb') as f:
            ciphertext = f.read()

        print("\nDang thu giai ma theo logic CBC Decrypt tieu chuan...")
        
        # 4. GIẢI MÃ NHƯNG KHÔNG GỠ PADDING
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data_with_padding = cipher.decrypt(ciphertext)
        
        print("\n==========================")
        print("GIAI MA THANH CONG!")
        print("==========================")
        
        print("\n--- NOI DUNG THO SAU KHI GIAI MA (BAO GOM PADDING) ---")
        # In ra dưới dạng hex để dễ phân tích
        print(decrypted_data_with_padding.hex())
        print("------------------------------------------------------\n")
        
        # Thử decode và in ra, bỏ qua các lỗi
        try:
            print("--- THU DECODE SANG TEXT (CO THE BI LOI) ---")
            print(decrypted_data_with_padding.decode('utf-8', errors='ignore'))
            print("--------------------------------------------\n")
        except:
            pass

        print("Dang ghi TOAN BO ket qua tho ra file 'flag_raw.bin'...")
        with open('flag_raw.bin', 'wb') as flag_file:
            flag_file.write(decrypted_data_with_padding)
        print("Da ghi xong. Vui long kiem tra file 'flag_raw.bin'.")

    except FileNotFoundError:
        print("Loi: Khong tim thay file 'out.bin'.")
    except Exception as e:
        print(f"\nDa xay ra mot loi khac: {e}")

if __name__ == '__main__':
    solve()