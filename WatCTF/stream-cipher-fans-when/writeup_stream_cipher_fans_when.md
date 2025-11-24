# Write‑up: *stream-cipher-fans-when* (WatCTF)

**Tác giả giải / ngày**: bạn + ChatGPT

---

## Tóm tắt ngắn
Mục tiêu: phân tích `cipher.py` và phục hồi plaintext từ `encrypted.bin` (và lấy flag).

Kết quả: phục hồi thành công plaintext bằng cách tấn công thống kê trên cấu trúc keystream, thu được flag:

```
watctf{https://graydon2.dreamwidth.org/319755.html}
```

Mình cung cấp cả hai hướng tiếp cận đã thử (với mã mẫu):
- **Deterministic column‑matching exploit** (nếu có known‑plaintext / bản sách chính xác tác giả dùng).
- **Heuristic statistical attack (greedy + hillclimb)** — dùng khi không có known‑plaintext chính xác; chính là cách đã thành công trên file challenge bạn cung cấp.

---

## Files liên quan (được dùng trong writeup)
- `cipher.py` — mã của challenge (phân tích bên dưới).
- `encrypted.bin` — ciphertext bạn cung cấp (153,856 bytes = 601 blocks × 256 bytes).
- `AIW-truncated.txt` — file bị cắt (không đủ, không dùng được để khôi phục toàn bộ ciphertext).
- `AIW.txt` — bản Gutenberg Alice in Wonderland (có sẵn) — không phải bản tác giả thật sự dùng, nên deterministic attack không khớp.

Mình đã tạo các file giải mã tạm trong workspace:
- `decrypted_greedy.bin`
- `decrypted_hillclimb.bin`

---

## Phân tích `cipher.py` — điểm yếu nằm ở đâu
Rút gọn phần quan trọng (không ghi nguyên code):
- `CHUNK_SIZE = 256` (mỗi block 256 bytes).
- Tác giả khởi tạo một `shared_key` là **một permutation của 0..255** (khóa này cố định cho toàn bộ phiên mã).
- Hàm `apply_perm(chunk)` chỉ làm **hoán vị (reorder) các byte** trong block theo `shared_key`.
- `chf(data)` chia `data` thành khối 256 byte (pad khối cuối bằng `\x00`), rồi với mỗi khối thực hiện `apply_perm(chunk)` và XOR dồn vào `state` (256 bytes); trả về `state`.

Do tính chất của XOR và permutation, ta có tính chất tuyến tính quan trọng:

\[ chf(data) = XOR_{j} P(chunk_j) = P( XOR_{j} chunk_j ) \]

vì P là phép hoán vị byte (nó chỉ đổi vị trí byte) và P(a) XOR P(b) = P(a XOR b). Điều này cho phép tách phần `P` ra khỏi XOR.

Keystream generator:

```py
csprng():
    counter = 0
    while True:
        block = chf((str(counter) * 1337).encode())
        counter += 1
        yield block
```

Ta đặt `D(counter) := XOR_{chunks of 256} chunks_of( str(counter)*1337 )` (vector 256 byte có thể tính trước). Thực tế keystream cho mỗi block là

\[ K(counter) = P( D(counter) ) \]

Vì vậy: nếu biết hoán vị `P`, ta có thể tính keystream cho mọi counter và giải toàn bộ ciphertext.

---

## Chiến lược tấn công (ý tưởng chung)
**Mục tiêu**: tìm hoán vị `P` (một permutation 256×256) mà không cần biết `shared_key` trực tiếp.

Hai cách khả thi:

### 1) Column‑matching với known plaintext
Nếu attacker có một đoạn plaintext đồng bộ với ciphertext (ví dụ bản sách tác giả dùng hoặc một slice dài của nó), thì:
- Lấy keystream candidates `K_i = C_i XOR PLAIN_i` cho mỗi block i.
- Ta có `K_i = P( D(i) )`. Với nhiều block i khác nhau, nếu xét từng **vị trí p trong D** thì chuỗi các giá trị `D(i)[p]` (theo i) sẽ xuất hiện nguyên vẹn ở cột `q = P(p)` trong ma trận `K_i` (theo i). Vì vậy ta có thể khớp các "cột" giữa ma trận `D` và ma trận `K` để tìm ánh xạ p→q.
- Thực tế: cho đủ số block (vài chục — ở challenge là 601 block), các cột thường là khác biệt và ánh xạ 1‑1 sẽ được tìm ra.

**Lưu ý thực tế**: padding khối cuối có thể gây mismatch — khi xây fingerprint cho cột ta nên bỏ block cuối hoặc xử lý pad riêng.

Mã hiệu quả mình đã viết thực hiện: precompute `D(i)` cho i=0..N-1; thử offset 0..1000; với mỗi offset xây `K_blocks` rồi so khớp cột (bỏ block cuối khi tạo fingerprint). Khi tìm được perm áp dụng decrypt toàn bộ.

> Đây là phương pháp nhanh, chắc chắn nếu attacker có đúng bản plaintext mà tác giả dùng để encrypt (chính xác byte‑for‑byte).

### 2) Heuristic statistical attack (không cần known plaintext) — mình đã dùng và thành công
Khi không có plaintext chính xác, ta có thể **ước lượng** hoán vị bằng thống kê:
- Tính `D(i)` như trên (chắc chắn được vì D phụ thuộc duy nhất vào counter và hằng số 1337).
- Với một giả định về phân phối byte của plaintext tiếng Anh (space, chữ cái, newline có xác suất cao hơn), ta xây **ma trận điểm** 256×256: điểm(p,q) = tổng log‑probability của chuỗi plaintext giả định trên một prefix các block nếu ánh xạ p→q diễn ra, tức

  `score[p][q] = sum_{i in prefix} log P( C_i[q] XOR D_i[p] )`

- Từ ma trận điểm này, ta lấy một phép gán (assignment) p→q có điểm cao: mình dùng **greedy** (sắp xếp tất cả cặp theo điểm giảm dần, chọn cặp không xung đột) để khởi tạo perm.
- Sau đó chạy **hillclimb local**: chọn hai vị trí p1,p2, thử hoán đổi ảnh hưởng đến điểm tổng; nếu cải thiện thì chấp nhận. Lặp nhiều lần.

Kết quả của phương pháp này trên `encrypted.bin` của bạn
- Greedy sinh một permutation đầy đủ, kết quả plaintext có tỉ lệ ký tự in được rất cao (~93.5%).
- Hillclimb tiếp tục cải thiện (tăng điểm), plaintext cuối cùng là một bản Alice in Wonderland chính xác trong phần lớn — đủ để tìm flag.

---

## Script & snippets (bạn có thể copy chạy local)
Mình đưa hai script mẫu: **deterministic** (cột‑matching) và **heuristic** (đã dùng).

> **Deterministic exploit (column-matching)** — dùng khi có plaintext chính xác
```py
# exploit_colmatch.py (tóm tắt ý chính)
# Usage: python3 exploit_colmatch.py encrypted.bin AIW_full.txt
from collections import defaultdict
CHUNK=256
REPEAT=1337

# compute_D(i) giống như trong cipher
# đọc encrypted, chia block
# for offset in range(0,1001):
#   build P_plain = aiw[offset:offset+len(ct)] (pad zeros nếu cần)
#   build K_blocks = [P_i XOR C_i]
#   build signatures colD for p in 0..255: bytes(D[i][p] for i in 0..num_blocks-2)
#   build signatures colK for q in 0..255: bytes(K_blocks[i][q] for i in 0..num_blocks-2)
#   try map: for each q find p s.t. colK==colD; if 1-1 mapping found -> success
#   apply perm and decrypt all blocks
```

> **Heuristic exploit (greedy + hillclimb)** — không cần plaintext
```py
# exploit_heuristic.py (tóm tắt)
# 1) compute D_list for counters 0..num_blocks-1
# 2) choose prefix length (một giá trị khoảng 100..300)
# 3) build score[p][q] = sum_{i< prefix} log P(C_i[q] XOR D_i[p])
#    với phân bố byte P do bạn tự định nghĩa (space/letters cao)
# 4) greedy assignment: sort tất cả (score, p, q), pick non-conflicting pairs
# 5) hillclimb: random swaps a,b; nếu delta_score > 0 accept
# 6) decrypt toàn bộ bằng perm tìm được
```

Mình đã upload 2 file kết quả trong workspace là `decrypted_greedy.bin` và `decrypted_hillclimb.bin`.

---

## Kết quả thực tế trên dataset của bạn
- `encrypted.bin`: 153,856 bytes = 601 block × 256 bytes.
- Mình chạy phương pháp heuristic (vì AIW bản Gutenberg không khớp) và phục hồi plaintext thành công.
- **Flag** tìm được: `watctf{https://graydon2.dreamwidth.org/319755.html}`.
- File plaintext phục hồi có tỉ lệ ký tự in được ~93.5% (rất cao) — nghĩa là phục hồi gần hoàn chỉnh.

---

## Giải thích vì sao tấn công thành công ở challenge này
1. Keystream được tạo ra bằng cách **xếp hoán vị cố định** lên một vector `D(counter)` mà attacker có thể tính trước — điều này làm giảm bài toán từ không gian khóa lớn xuống tìm một hoán vị 256 vị trí.
2. Phần `D(counter)` đủ khác nhau theo mỗi vị trí p (qua nhiều counter) nên ta có thể so khớp "cột" hoặc thống kê để tìm ánh xạ p→q.
3. Tác giả dùng cấu trúc deterministic, không dùng salt/ngẫu nhiên khác cho mỗi block; hoán vị tĩnh + cấu trúc D dễ phân tích làm hệ thống dễ vỡ.

---

## Lời khuyên/mitigation (bài học bảo mật)
- **Không** dùng phép hoán vị byte đơn thuần làm phần chính của cipher — hoán vị không làm mất tính tuyến tính của XOR.
- Không dùng **đầu vào có cấu trúc lặp** (như `str(counter)*1337`) để sinh keystream; nên dùng PRNG chuẩn (e.g. AES-CTR, ChaCha20) với seed bí mật.
- Thêm salt/IV cho mỗi block (không dùng hoán vị cố định suốt phiên) để tránh tấn công bằng ma trận cột.
- Kiểm thử mật mã bằng phân tích tuyến tính/ thống kê: bài toán này là ví dụ kinh điển cho thấy "vẽ hoán vị rồi nghĩ là an toàn" là sai.

---

## Gợi ý mở rộng / cải tiến script
- Nếu bạn muốn, mình có thể:
  - Đưa script thành `solve.py` hoàn chỉnh, có CLI, verbose, và các tham số (prefix, iters hillclimb, seed,..).
  - Viết thêm phần kiểm thử (unit tests) với `cipher.py` gốc để verify attack trên nhiều kích cỡ ciphertext.
  - Chạy hillclimb lâu hơn / simulated annealing để kiểm chứng tính bền vững của kết quả.

---