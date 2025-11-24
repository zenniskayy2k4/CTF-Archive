#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// --- Triển khai lại bộ tạo số ngẫu nhiên của Microsoft Visual C++ (msvcrt) ---
static unsigned int next_seed = 1;

// Tương đương srand()
void my_srand(unsigned int seed) {
    next_seed = seed;
}

// Tương đương rand() của MSVCRT
int my_rand(void) {
    // SỬ DỤNG CÁC HẰNG SỐ CỦA MICROSOFT
    next_seed = next_seed * 214013 + 2531011;
    
    // Kết quả vẫn là một số 15-bit
    return (next_seed >> 16) & 0x7FFF;
}

// Hàm kiểm tra xem một chuỗi có hoàn toàn là ký tự in được không
int is_printable_string(const unsigned char* str, int len) {
    for (int i = 0; i < len; ++i) {
        if (!isprint(str[i])) {
            return 0; // Không phải ký tự in được
        }
    }
    return 1; // Tất cả đều là ký tự in được
}

int main() {
    // Dữ liệu đầu vào
    unsigned char encrypted_flag[] = {
        0x3e, 0xc6, 0x3c, 0xc4, 0x1f, 0x1a, 0xc1, 0x98, 0x06, 0x51, 0x72, 0x6a,
        0xb3, 0xce, 0x29, 0x48, 0x88, 0x2b, 0x87, 0x9c, 0x19, 0x67, 0x12, 0x69,
        0x96, 0x3e, 0x39, 0x10, 0x3c, 0x83, 0xeb, 0xd6, 0xef, 0x17, 0x3d, 0x60,
        0xc7, 0x6e, 0xe5
    };
    long approx_time = 1755860000;
    int flag_len = sizeof(encrypted_flag);
    unsigned char decrypted_flag[100];

    printf("[*] Bat dau brute-force seed trong khoang [%ld, %ld]...\n", approx_time, approx_time + 9999);

    for (long offset = 0; offset < 10000; ++offset) {
        long potential_seed = approx_time + offset;
        
        my_srand(potential_seed);

        for (int i = 0; i < 1000; ++i) {
            my_rand();
        }

        for (int i = 0; i < flag_len; ++i) {
            int key_byte = my_rand() % 256;
            decrypted_flag[i] = encrypted_flag[i] ^ key_byte;
        }
        decrypted_flag[flag_len] = '\0';

        if (strstr((const char*)decrypted_flag, "{") != NULL &&
            strstr((const char*)decrypted_flag, "}") != NULL &&
            is_printable_string(decrypted_flag, flag_len)) {

            printf("\n========================================\n");
            printf("[+] Tim thay flag!\n");
            printf("[+] Seed chinh xac la: %ld\n", potential_seed);
            printf("[+] Flag: %s\n", decrypted_flag);
            printf("========================================\n");
            return 0;
        }
    }

    printf("\n[!] Khong tim thay flag.\n");
    return 1;
}