Đó chính là một lỗ hổng kinh điển trong các API GraphQL, thường được gọi là **Insecure Direct Object Reference (IDOR)** hoặc lỗi kiểm soát quyền truy cập. Hệ thống đã xác thực bạn đã đăng nhập, nhưng lại "quên" kiểm tra xem bạn có *quyền* xem ghi chú riêng tư của người dùng khác hay không, cho phép bạn đi đường vòng từ dữ liệu công khai để truy cập dữ liệu nhạy cảm.

Chào bạn, bạn đã tìm ra một điểm cực kỳ quan trọng! Giao diện này là một **GraphQL Playground**, một công cụ tương tác để truy vấn API GraphQL của trang web. File `schema.graphql.txt` mà bạn cung cấp chính là "bản đồ" của toàn bộ API.

Mục tiêu của chúng ta là phân tích bản đồ này, tìm ra những điểm yếu hoặc những nơi có thể chứa thông tin bí mật (flag) và xây dựng các câu truy vấn (query) để lấy chúng.

Dưới đây là kế hoạch tấn công từng bước một.

### Phân tích Schema (Bản đồ API)

Hãy nhìn vào những điểm đáng ngờ trong schema:

1.  **Queries (Truy vấn để đọc dữ liệu):**
    *   `publicRecipes`: Các công thức công khai. Đây là nơi tốt để bắt đầu, có thể nó sẽ tiết lộ tên người dùng hoặc các thông tin hữu ích khác.
    *   `secretRecipes`: **Điểm đáng ngờ số 1.** Các công thức bí mật chắc chắn là nơi chúng ta muốn vào. Rất có thể truy vấn này yêu cầu phải đăng nhập.
    *   `me`: Lấy thông tin của người dùng đã đăng nhập.

2.  **Mutations (Hành động để thay đổi/lấy dữ liệu):**
    *   `login(username: String!, password: String!): AuthPayload!`: **Đây là cửa vào.** Chúng ta cần tìm ra `username` và `password` để đăng nhập. Sau khi đăng nhập thành công, chúng ta sẽ nhận được một `token` để xác thực cho các truy vấn sau.

3.  **Types (Các loại đối tượng):**
    *   `User`: Đối tượng người dùng có các trường rất thú vị:
        *   `notes`: Ghi chú.
        *   `privateNotes`: **Điểm đáng ngờ số 2.** Ghi chú riêng tư! Đây là một mục tiêu hàng đầu. Rất có thể flag được giấu ở đây.

### Kế hoạch tấn công

**Hướng 2 (Khả năng cao nhất): Khai thác lỗi ủy quyền (Authorization Bypass)**

Đây là hướng tấn công tinh vi và có khả năng thành công cao nhất. Ý tưởng là: hệ thống có thể kiểm tra xem bạn *đã đăng nhập chưa* nhưng lại quên kiểm tra xem bạn có *quyền xem* dữ liệu riêng tư của người khác không.

Chúng ta sẽ xây dựng một query phức tạp để đi từ một công thức công khai, tìm ra chủ sở hữu của nhà cung cấp nguyên liệu, và sau đó đọc trộm `privateNotes` của người đó.

Dán query này vào và chạy:

```graphql
query getSupplierOwnerPrivateNotes {
  publicRecipes {
    name
    ingredients {
      name
      supplier {
        name
        owner {
          username
          notes
          privateNotes 
        }
      }
    }
  }
}
```

**Phân tích query này:**
1.  `publicRecipes`: Bắt đầu từ điểm ai cũng thấy.
2.  `ingredients`: Lấy các nguyên liệu.
3.  `supplier`: Lấy nhà cung cấp.
4.  `owner`: Lấy thông tin người chủ của nhà cung cấp đó.
5.  `privateNotes`: **Đây là bước tấn công!** Chúng ta đang yêu cầu xem ghi chú riêng tư của người chủ đó, dù chúng ta đang đăng nhập bằng tài khoản khác. Nếu hệ thống bị lỗi, nó sẽ trả về nội dung của `privateNotes`, và flag rất có thể nằm ở đó.