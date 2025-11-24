from wasmtime import Store, Module, Instance, Linker, Func, FuncType

def parity(n: int) -> int:
    """Hàm `x` được import bởi WASM, tính parity bit."""
    result = 0
    while n != 0:
        result ^= n & 1
        n >>= 1
    return result

def main():
    print("Bắt đầu quá trình giải mã bằng brute-force mapping...")

    # --- Tải module WASM ---
    store = Store()
    module = Module.from_file(store.engine, './vault.wasm')
    linker = Linker(store.engine)

    # --- Liên kết hàm `env.x` mà WASM cần ---
    parity_func_type = FuncType([ValType.i32()], [ValType.i32()])
    linker.define("env", "x", Func(store, parity_func_type, parity))

    print("Đang xây dựng bản đồ giải mã ngược. Quá trình này sẽ mất khoảng 1-2 phút...")
    
    # --- Bước 1: Xây dựng bản đồ giải mã ---
    reverse_map = {}
    for original_byte in range(256):
        # Tạo một INSTANCE MỚI cho mỗi lần thử để đảm bảo bộ nhớ luôn sạch
        instance = linker.instantiate(store, module)
        memory = instance.exports(store)["memory"]
        unlock_func = instance.exports(store)["unlock"]

        # Ghi byte cần thử vào đầu bộ nhớ
        memory.write(store, b'\x00', original_byte)

        # Chạy hàm unlock (kết quả không quan trọng)
        unlock_func(store)

        # Đọc byte đã bị biến đổi
        encrypted_byte = memory.read(store, 0, 1)[0]
        
        # Lưu vào bản đồ
        reverse_map[encrypted_byte] = original_byte

        # In tiến trình
        if (original_byte + 1) % 16 == 0:
            print(f"  Đã xử lý {original_byte + 1}/256 byte...")

    print("Đã tạo bản đồ giải mã thành công!")

    # --- Bước 2: Giải mã dữ liệu thực tế ---
    
    # Dữ liệu bạn đã dump, không còn sai sót
    hex_dump = "b5 03 00 00 e8 c6 66 0c d7 c1 c7 64 9d 11 1c be 12 75 58 ca 6e 00 4e 4c 45 2d a4 46 89 8c d5 65 35 bb 9b c2 cb eb 36 30 b5 90 2a aa 35 44 d1 dc ba b8 05 61 5a fd f9 6b 6f cb 5b 7e 5a da be f4 b6 0f eb 17 05 45 b0 47 f3 4a 17 f3 71 11 da 5a 2b 86 ea 79 eb 1a a2 ec 17 a1 0b 83 79 6d d4 f3 df 96 5b 57 41 7f 4e e7 68 e9 8f 48 41 77 0e 1b 9f 1a ad 3e f8 a4 89 d3 63 52 40 b8 ae c6 00"
    all_bytes = bytes.fromhex(hex_dump.replace(' ', ''))
    encrypted_data = all_bytes[4:]

    decrypted_bytes = []
    for byte in encrypted_data:
        if byte == 0x00:
            break
        # Dùng bản đồ để tra cứu
        decrypted_bytes.append(reverse_map[byte])

    flag = bytes(decrypted_bytes).decode('utf-8')

    print("\n----------------------------------")
    print("THÀNH CÔNG! Flag là:")
    print(flag)
    print("----------------------------------")

# Cần thêm đoạn này để chạy được wasmtime
# It seems wasmtime library has a bug with FuncType and ValType not being defined in the global scope
# So we need to import them manually
from wasmtime import ValType
if __name__ == "__main__":
    main()