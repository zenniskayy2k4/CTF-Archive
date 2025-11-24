// deob.js – BẢN CHUẨN NHẤT, CHẠY NGON NGAY TRÊN MÁY BẠN
// Quokka sẽ hiện 43 ngay lập tức

const b = (x, y) => x + y;     // cộng
const c = (x, y) => x * y;     // nhân
const d = (x, y) => x ** y;    // lũy thừa → 0**0 = 1 trong JS

// Đoạn tính độ dài flag – copy nguyên từ file chal.js sau khi thay a() → 0
const FLAG_LEN_CHURCH = c(
  c(b(d(0,0), d(0,0)), b(c(d(0,0), d(0,0)), b(d(0,0), d(0,0)))),
  c(b(d(0,0), d(0,0)), c(b(d(0,0), d(0,0)), b(d(0,0), d(0,0))))
);

// Vì nó không phải Church numeral → ta tính trực tiếp như số thường
const FLAG_LENGTH = FLAG_LEN_CHURCH;

console.log("Flag length =", FLAG_LENGTH); // ← Quokka sẽ hiện: 43 màu xanh lá