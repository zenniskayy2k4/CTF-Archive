async function solveByMapping() {
    try {
        // Bước 1: Tải và khởi tạo module WASM
        const vault = await WebAssembly.instantiateStreaming(fetch("vault.wasm"), {
            env: {
                x: (number) => 0, // Cung cấp hàm giả, không quan trọng
            }
        });

        const memory = new Uint8Array(vault.instance.exports.memory.buffer);
        const unlockFunc = vault.instance.exports.unlock;
        console.log("WASM module loaded. Starting decryption mapping...");

        // Bước 2: Xây dựng bản đồ giải mã ngược
        const reverseMap = new Map();

        for (let originalByte = 0; originalByte < 256; originalByte++) {
            // Đặt một byte duy nhất vào đầu bộ nhớ
            memory[0] = originalByte;
            // Đặt ký tự null để kết thúc chuỗi
            memory[1] = 0;

            // Chạy hàm `unlock`. Chúng ta không quan tâm kết quả (sẽ là false).
            // Điều quan trọng là các hàm biến đổi BÊN TRONG `unlock`
            // đã được thực thi trên byte chúng ta đặt ở memory[0].
            unlockFunc();

            // Đọc byte đã bị biến đổi tại vị trí cũ
            const encryptedByte = memory[0];

            // Lưu vào bản đồ: encrypted_byte => original_byte
            reverseMap.set(encryptedByte, originalByte);
        }

        console.log("Decryption map created successfully.", reverseMap);

        // Bước 3: Đọc dữ liệu mục tiêu và áp dụng bản đồ
        const targetDataAddress = 3588; // Địa chỉ bắt đầu của chuỗi mã hóa
        const encryptedData = memory.slice(targetDataAddress, targetDataAddress + 256);

        const decrypted_bytes = [];
        for (const byte of encryptedData) {
            if (byte === 0) {
                break; // Dừng khi gặp byte null
            }
            // Dùng bản đồ để tra cứu ký tự gốc
            decrypted_bytes.push(reverseMap.get(byte));
        }

        // Bước 4: Chuyển đổi thành chuỗi và hiển thị flag
        const flag = new TextDecoder().decode(new Uint8Array(decrypted_bytes));

        console.log("SUCCESS! The flag is:", flag);
        const field = document.getElementById("vault");
        field.value = flag;
        field.classList.remove("is-danger");
        field.classList.add("is-success");

    } catch (error) {
        console.error("An error occurred during the solving process:", error);
    }
}

// Chạy hàm giải của chúng ta
solveByMapping();