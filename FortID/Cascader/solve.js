"use strict";

// Yêu cầu thư viện crypto gốc của Node.js
const { createHash, createDecipheriv } = require('node:crypto');

async function solveTheRightWay() {

    // --- BƯỚC 1: TÍNH TOÁN HẰNG SỐ TỪ ĐỊNH NGHĨA GỐC ---
    // Đây là bước quan trọng nhất để loại bỏ mọi lỗi sao chép.
    const KEY_SIZE_BITS = 256n;
    const MAX_INT = 1n << KEY_SIZE_BITS;
    const MOD = MAX_INT - 189n; 
    const SEED = MAX_INT / 5n;

    // Các giá trị công khai từ output.txt
    const alicePublic = 81967497404473670873986762408662347640688858544889917659709378751872081150739n;
    const bobPublic = 25638634989672271296647305730621408042240305773269414164982933528002524403752n;
    const ct_hex = "e2f84b71e84c8d696923702ddb1e35993e9108289e2d14ae8f05441ad48d1a67ead74f5f230d39dbfaae5709448c2690237ac6ab88fc26c8f362284d1e8063491d63f7c15cc3b024c62b5069605b73dd2c54fdcb2823c0c235b20e52dc5630c5f3";
    
    // --- BƯỚC 2: CÁC HÀM GỐC TỪ CHALL.JS ---
    
    function linearRecurrence(seed, exponents) {
        let result = seed;
        let exp = 1n;
        while (exponents > 0n) {
            if (exponents % 2n === 1n) {
                let mult = 1n;
                for (let i = 0n; i < exp; i++) {
                    result = 3n * result * mult % MOD;
                    mult <<= 1n;
                }
            }
            exponents >>= 1n;
            exp++;
        }
        return result;
    }
    
    function bigIntToFixedBE(n, lenBytes) {
      let hex = n.toString(16);
      if (hex.length % 2) hex = "0" + hex;
      const buf = Buffer.from(hex, "hex");
      if (buf.length > lenBytes) {
        return buf.slice(-lenBytes);
      } else if (buf.length < lenBytes) {
        const pad = Buffer.alloc(lenBytes - buf.length, 0);
        return Buffer.concat([pad, buf]);
      }
      return buf;
    }
    
    function sha256(buf) {
      return createHash("sha256").update(buf).digest();
    }

    // --- BƯỚC 3: XÁC MINH VÀ GIẢI ---

    const alicePrivate = 969n;

    // Sanity Check: Xác minh lại alicePrivate = 969 là đúng với các hằng số vừa tính
    console.log(">> Đang xác minh lại khóa riêng...");
    const calculatedAlicePublic = linearRecurrence(SEED, alicePrivate);
    if (calculatedAlicePublic !== alicePublic) {
        console.error("!!! LỖI NGHIÊM TRỌNG: Khóa riêng 969 không còn đúng. Thử thách có thể đã thay đổi.");
        return;
    }
    console.log("[+] Khóa riêng 969 đã được xác minh là chính xác.");
    
    // Tính aliceShared bằng các giá trị đã được xác minh.
    console.log(">> Đang tính toán aliceShared...");
    const aliceShared = linearRecurrence(bobPublic, alicePrivate);
    console.log(`[+] Giá trị aliceShared chính xác: ${aliceShared}`);

    // Tạo khóa AES.
    console.log(">> Đang tạo khóa AES...");
    const sharedBytes = bigIntToFixedBE(aliceShared, 32);
    const aesKey = sha256(sharedBytes);
    
    // Giải mã cờ.
    console.log(">> Đang giải mã cờ...");
    const ct_buf = Buffer.from(ct_hex, "hex");
    const iv = ct_buf.slice(0, 12);
    const tag = ct_buf.slice(-16);
    const ciphertext = ct_buf.slice(12, -16);

    try {
        const decipher = createDecipheriv('aes-256-gcm', aesKey, iv);
        decipher.setAuthTag(tag);
        let decrypted = decipher.update(ciphertext, 'binary', 'utf8');
        decrypted += decipher.final('utf8');
        
        console.log("\n" + "=".repeat(55));
        console.log("  [!!!] GIẢI MÃ THÀNH CÔNG !!!");
        console.log(`        FLAG: ${decrypted}`);
        console.log("=".repeat(55));

    } catch (err) {
        console.error("\n[-] Lỗi giải mã:", err.message);
    }
}

solveTheRightWay();