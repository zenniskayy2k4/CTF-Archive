// solve.js
import init, { check_flag } from './tfw_no_stack_locals.js';

async function main() {
    await init('./tfw_no_stack_locals_bg.wasm');

    let flag = "watctf{";
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!@#$%^&*-+={}'.,?`~";

    while (!flag.endsWith("}")) {
        let foundChar = false;
        for (const char of charset) {
            const guess = flag + char;
            process.stdout.write(`\rTrying: ${guess}`);

            // Giả định: hàm check_flag sẽ không bị crash hoặc
            // trả về một kết quả khác biệt cho một tiền tố đúng.
            // Trong nhiều bài RE, hàm so sánh sẽ là:
            // for (i=0; i<len; i++) { if (transformed_input[i] != correct_hash[i]) return false; }
            // Chúng ta khai thác điều đó.
            
            // Một cách tiếp cận khác là debug WASM trong trình duyệt và đặt breakpoint.
            // Khi `check_flag` được gọi, chúng ta có thể xem bộ nhớ và tìm thấy flag đã được giải mã
            // hoặc chuỗi được dùng để so sánh.
            
            // Nhưng hãy thử bruteforce trước.
            // Để bruteforce hoạt động, chúng ta cần một tín hiệu.
            // Ở đây, tín hiệu duy nhất là true/false.
            // Nếu check_flag(watctf{a}) là false và check_flag(watctf{b}) cũng là false,
            // chúng ta không có thông tin gì.

            // => Lời giải không phải là bruteforce.
        }
        // Nếu không tìm thấy, thoát.
        if (!foundChar) {
             // console.log("\nBruteforce failed.");
             // break;
        }
    }
}


// === Lời Giải Đúng ===
// Bài toán này là một dạng "Side-Channel Attack" rất cổ điển.
// Logic trong WASM, khi xử lý một ký tự sai, sẽ thoát ra sớm hơn so với khi xử lý một ký tự đúng.
// Sự khác biệt về thời gian này rất nhỏ, nhưng có thể đo lường được.

async function solveWithTimingAttack() {
    await init('./tfw_no_stack_locals_bg.wasm');
    
    let flag = "watctf{";
    // Giới hạn bộ ký tự để tăng tốc độ
    const charset = "abcdefghijklmnopqrstuvwxyz0123456789_}";
    
    console.log("Starting timing attack...");

    while (!flag.endsWith("}")) {
        let bestChar = '';
        let maxTime = -1;

        for (const char of charset) {
            const guess = flag + char;
            
            // Đo thời gian thực thi
            const start = performance.now();
            for (let i = 0; i < 100; i++) { // Chạy nhiều lần để kết quả đo chính xác hơn
                check_flag(guess);
            }
            const end = performance.now();
            const duration = end - start;

            // Ký tự nào khiến hàm chạy lâu nhất có khả năng là ký tự đúng
            if (duration > maxTime) {
                maxTime = duration;
                bestChar = char;
            }
        }
        
        flag += bestChar;
        console.log(`Found next char: ${bestChar}. Current flag: ${flag}`);
    }
    
    console.log(`\nFinal Flag: ${flag}`);
}


solveWithTimingAttack();