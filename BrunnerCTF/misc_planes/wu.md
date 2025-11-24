### **[Write-up] Planes! - Hành trình khám phá những mặt phẳng bit ẩn giấu**

Đây là bài hướng dẫn giải chi tiết cho thử thách Steganography có tên **Planes!**. Chúng ta sẽ đi từ việc phân tích các manh mối trong đề bài cho đến khi tìm ra flag cuối cùng.

#### **1. Phân tích đề bài (Clue Analysis)**

Trước khi bắt tay vào làm, hãy cùng phân tích các gợi ý mà tác giả đã cung cấp:

*   **Tên bài: `Planes!`**
    *   Từ "Planes" (máy bay) trong ngữ cảnh Steganography thường là một cách chơi chữ, ám chỉ đến **Bit Planes** (mặt phẳng bit) hoặc Color Planes (kênh màu). Đây là manh mối lớn nhất cho chúng ta biết rằng dữ liệu có thể đang được ẩn giấu trong các lớp bit của hình ảnh.

*   **Mô tả: "Everything is always in *order*!"**
    *   Từ "*order*" (thứ tự) được nhấn mạnh. Điều này gợi ý rằng dữ liệu không nằm ở một chỗ duy nhất mà đã bị phân mảnh ra nhiều nơi. Nhiệm vụ của chúng ta là phải tìm và lắp ráp chúng lại theo một "thứ tự" chính xác.

*   **Mô tả: "I just hope they don't *byte*..."**
    *   Đây là một cách chơi chữ kinh điển giữa "bite" (cắn) và "*byte*". Manh mối này hướng chúng ta đến việc thao tác ở cấp độ bit/byte và gợi ý về nội dung của flag.

**Kết luận ban đầu:** Giả thuyết mạnh nhất là flag đã được chia nhỏ và giấu trong nhiều mặt phẳng bit (Bit Planes) khác nhau. Chúng ta cần tìm ra các plane này và trích xuất dữ liệu theo đúng thứ tự.

#### **2. Công cụ & Hướng giải quyết**

Với giả thuyết về Bit Plane, công cụ hoàn hảo cho nhiệm vụ này là **StegSolve**. Đây là một công cụ mạnh mẽ cho phép chúng ta dễ dàng xem và phân tích từng mặt phẳng bit của hình ảnh.

Hướng giải quyết của chúng ta sẽ là:
1.  Dùng StegSolve để duyệt qua tất cả các mặt phẳng bit.
2.  Xác định những mặt phẳng có chứa dữ liệu (thay vì chỉ là nhiễu trắng ngẫu nhiên).
3.  Sử dụng tính năng `Data Extract` của StegSolve để kết hợp dữ liệu từ các mặt phẳng đã tìm được và lấy flag.

#### **3. Các bước thực hiện chi tiết**

**Bước 1: Mở ảnh và khám phá các Bit Plane**

*   Mở file `plane.png` bằng StegSolve.
*   Sử dụng các phím mũi tên `◀` và `▶` ở phía dưới để duyệt qua các chế độ xem khác nhau. Hãy tập trung vào các mặt phẳng bit, ví dụ như: `Red plane 0-7`, `Green plane 0-7`, `Blue plane 0-7`.

Trong quá trình duyệt, bạn sẽ nhận thấy rằng hầu hết các mặt phẳng chỉ là nhiễu trắng. Tuy nhiên, một vài trong số chúng chứa các đường nét và cấu trúc rất rõ ràng. Đây chính là những nơi chứa các mảnh của flag.

**Bước 2: Xác định các Bit Plane chứa dữ liệu**

Sau khi duyệt, ta có thể xác định được 4 mặt phẳng chứa các mảnh ghép của flag:
*   **Red plane 1**
*   **Green plane 3**
*   **Green plane 4**
*   **Blue plane 2**

**Bước 3: Sử dụng Data Extract để trích xuất Flag**

Đây là bước quan trọng nhất. Chúng ta sẽ yêu cầu StegSolve kết hợp dữ liệu từ 4 mặt phẳng đã tìm thấy theo một thứ tự cụ thể.

*   Trên thanh menu, chọn `Analyse` -> `Data Extract`.
*   Một cửa sổ mới sẽ hiện ra. Hãy thiết lập các tùy chọn như sau:

    *   **Bit Planes to Extract from:** Tick vào các ô:
        *   `Red: 1`
        *   `Green: 3, 4`
        *   `Blue: 2`
    *   **Bit Plane Order:** Chọn `RGB`. StegSolve sẽ đọc lần lượt một bit từ kênh Red, rồi đến Green, rồi đến Blue.
    *   **Extract by:** Chọn `Row`. Dữ liệu được sắp xếp theo hàng ngang.
    *   **Bit Order:** Chọn `LSB First`. Đây là thứ tự bit phổ biến nhất.

**Bước 4: Xem kết quả**

*   Để kết quả hiển thị gọn gàng hơn, hãy **bỏ tick** ở ô `Include Hex Dump In Preview`.
*   Nhấn nút **Preview**.

Ngay lập tức, bạn sẽ thấy flag xuất hiện trong khung xem trước!


*(Bạn có thể thêm ảnh chụp màn hình cấu hình StegSolve của mình vào đây để write-up trực quan hơn)*

#### **4. Kết quả**

Flag cuối cùng được trích xuất là:
```
brunner{M0000000M!!!_Th3_Pl4N3_B1T_M3!}
```
Flag này là một cách chơi chữ rất thông minh: **"M!!! The Plane Bit Me!"** (Á!!! Mặt phẳng bit đã cắn tôi!), khớp hoàn hảo với manh mối *"I just hope they don't **byte**..."*.