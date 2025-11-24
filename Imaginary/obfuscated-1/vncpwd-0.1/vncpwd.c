/*
   VNC Password Decrypter - MODIFIED FOR CTF
*/

#include <stdio.h>
#include <stdlib.h>
// #include <sys/types.h> // Không cần thiết trên Windows
// #include <unistd.h>      // Không cần thiết trên Windows
#include "d3des.h"

// Khóa tùy chỉnh từ file gốc
static unsigned char obfKey[8] = {23,82,107,6,35,78,88,7};

// Sửa đổi hàm này để trả về kết quả thay vì chỉ in ra
void decryptPw( unsigned char *encrypted_input, char *decrypted_output ) {
    // Thiết lập khóa DES cho việc giải mã
    deskey(obfKey, DE1);
    
    // Thực hiện giải mã
    des(encrypted_input, (unsigned char*)decrypted_output);
    
    // Đảm bảo chuỗi được kết thúc bằng null
    decrypted_output[8] = '\0';
}

int main(int argc, char *argv[]) {
    // Mật khẩu mã hóa từ Registry Explorer, được viết dưới dạng mảng byte
    unsigned char encrypted_password[8] = {0x7E, 0x9B, 0x31, 0x12, 0x48, 0xB7, 0xC8, 0xA8};
    
    // Buffer để lưu trữ mật khẩu đã giải mã
    char decrypted_password[9];
    
    printf("[*] Gia tri ma hoa: 7E9B311248B7C8A8\n");
    printf("[*] Su dung khoa tuy chinh: {23,82,107,6,35,78,88,7}\n");
    // Gọi hàm giải mã
    decryptPw(encrypted_password, decrypted_password);

    // In kết quả cuối cùng
    printf("\n[+] Mat khau da giai ma: %s\n", decrypted_password);

    return 0;
}