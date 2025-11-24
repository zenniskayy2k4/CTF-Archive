#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

// ... (giữ nguyên các hàm hex_to_bytes và is_all_uppercase) ...
void hex_to_bytes(const char* hex_str, unsigned char* byte_array, size_t* byte_len) {
    *byte_len = strlen(hex_str) / 2;
    for (size_t i = 0; i < *byte_len; i++) {
        sscanf(hex_str + 2 * i, "%2hhx", &byte_array[i]);
    }
}

bool is_all_uppercase(const unsigned char* str, size_t len) {
    if (len < 10) return false;
    for (size_t i = 0; i < len; i++) {
        if (!isupper(str[i])) {
            return false;
        }
    }
    return true;
}


int main() {
    const char* hex_encoded_flag = "59544c5065417167414774786762784c7a63646b6874417b76724178417a6b787f66724c7d7576747672794c7769687e794c7b7b75667b6b687b6d747878737f7970794c64717b6a667e797a4176644c6d756f7d6f70744c757f794c7c6169797863674c647c647d797a737d3f6e14";
    
    unsigned char encrypted_bytes[256];
    size_t encrypted_len;

    hex_to_bytes(hex_encoded_flag, encrypted_bytes, &encrypted_len);

    // THAY SỐ NÀY BẰNG KẾT QUẢ TỪ SCRIPT PYTHON
    time_t target_timestamp = 1757994143; 
    
    printf("Đang kiểm tra với timestamp: %ld\n", target_timestamp);

    // Sử dụng chính xác timestamp đã tìm được
    srand((unsigned int)target_timestamp +1);
    unsigned char key_byte_1 = rand() & 0xFF;
    unsigned char key_byte_2 = rand() & 0xFF;

    unsigned char decrypted_bytes[256];
    for (size_t i = 0; i < encrypted_len; i++) {
        if (i % 2 == 0) {
            decrypted_bytes[i] = encrypted_bytes[i] ^ key_byte_1;
        } else {
            decrypted_bytes[i] = encrypted_bytes[i] ^ key_byte_2;
        }
    }
    decrypted_bytes[encrypted_len] = '\0'; // Thêm ký tự kết thúc chuỗi

    if (is_all_uppercase(decrypted_bytes, encrypted_len)) {
        printf("\n[+] THÀNH CÔNG!\n");
        printf("[+] Key XOR (hex): 0x%02x, 0x%02x\n", key_byte_1, key_byte_2);
        printf("[+] Chuỗi đã giải mã Enigma: %s\n", decrypted_bytes);
        return 0;
    }

    printf("\n[-] Không đúng. Có thể có sai lệch 1-2 giây hoặc vấn đề về múi giờ.\n");
    return 1;
}