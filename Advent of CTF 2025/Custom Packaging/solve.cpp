#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring> // memcpy, memcmp
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm> // std::all_of, std::transform
#include <openssl/sha.h>

// --- CẤU HÌNH ---
const std::string FILENAME = "ks_operations.kcf";
// Đã thêm lại CHARSET bị thiếu
const char* CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"; 
const int CHARSET_LEN = 36;

// Global Data
std::vector<unsigned char> FILE_DATA;
std::vector<unsigned char> SALT;
unsigned long long FAT_OFFSET;
unsigned long long DATA_OFFSET;
std::atomic<bool> FOUND(false);
std::mutex PRINT_MUTEX;

// --- RC4 ---
struct RC4_State {
    unsigned char S[256];
    int i, j;
};

inline void rc4_init(RC4_State* state, const unsigned char* key, int key_len) {
    for (int i = 0; i < 256; i++) state->S[i] = i;
    state->i = 0;
    state->j = 0;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + state->S[i] + key[i % key_len]) & 0xFF;
        std::swap(state->S[i], state->S[j]);
    }
}

inline void rc4_crypt(RC4_State* state, const unsigned char* in, unsigned char* out, int len) {
    int i = state->i;
    int j = state->j;
    for (int k = 0; k < len; k++) {
        i = (i + 1) & 0xFF;
        j = (j + state->S[i]) & 0xFF;
        std::swap(state->S[i], state->S[j]);
        out[k] = in[k] ^ state->S[(state->S[i] + state->S[j]) & 0xFF];
    }
    state->i = i;
    state->j = j;
}

// --- CHECK LOGIC ---
bool check_identifier(const std::string& identifier) {
    // 1. KDF: SHA256(Salt + Identifier)
    unsigned char key[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, SALT.data(), SALT.size());
    SHA256_Update(&sha256, identifier.c_str(), identifier.length());
    SHA256_Final(key, &sha256);

    // 2. Decrypt FAT Entry #0
    RC4_State rc4;
    rc4_init(&rc4, key, SHA256_DIGEST_LENGTH);

    unsigned char entry[96];
    const unsigned char* fat_src = FILE_DATA.data() + FAT_OFFSET;
    rc4_crypt(&rc4, fat_src, entry, 96);

    // --- Parse FAT Entry ---
    unsigned long long f_off = 0;
    unsigned int f_sz = 0; // Size 4 bytes
    std::memcpy(&f_off, &entry[4], 8); 
    std::memcpy(&f_sz, &entry[12], 4); 

    // Sanity Check Size
    if (f_sz == 0 || f_sz > 100000000) return false; 

    // --- Tính toán name_len (Đã sửa: đưa ra ngoài if/else) ---
    int name_len = -1;
    for (int i = 0; i < 64; ++i) {
        if (entry[i] == 0) { name_len = i; break; }
    }
    
    // Nếu kiểm tra identifier cụ thể 'ks2025' để debug
    if (identifier == "ks2025") {
        if (name_len < 3) return false;
        
        // Check Magic Bytes file đầu tiên
        unsigned char file_header[4];
        RC4_State rc4_file;
        
        // HINT 2 UPDATE: Per-file key = SHA256(master_key || index || offset) truncated
        // Index 0 (4 byte LE) + Offset (8 byte LE)
        unsigned char idx_bytes[4] = {0,0,0,0};
        unsigned char off_bytes[8];
        std::memcpy(off_bytes, &f_off, 8);
        
        // Input: MasterKey(32) + Index(4) + Offset(8)
        unsigned char derived_input[32 + 4 + 8];
        std::memcpy(derived_input, key, 32);
        std::memcpy(derived_input + 32, idx_bytes, 4);
        std::memcpy(derived_input + 36, off_bytes, 8);
        
        unsigned char derived_hash[SHA256_DIGEST_LENGTH];
        SHA256(derived_input, sizeof(derived_input), derived_hash);
        
        // Truncate to 16 bytes
        rc4_init(&rc4_file, derived_hash, 16);
        
        const unsigned char* data_src = FILE_DATA.data() + DATA_OFFSET + f_off;
        rc4_crypt(&rc4_file, data_src, file_header, 4);

        bool is_office = false;
        if (memcmp(file_header, "\x50\x4B\x03\x04", 4) == 0) is_office = true;
        if (memcmp(file_header, "\xD0\xCF\x11\xE0", 4) == 0) is_office = true;

        if (is_office) {
            std::lock_guard<std::mutex> lock(PRINT_MUTEX);
            std::cout << "\n[!!!] KEY FOUND [!!!]" << std::endl;
            std::cout << "      Identifier: " << identifier << std::endl;
            std::cout << "      Filename:   " << std::string((char*)entry, name_len) << std::endl;
            FOUND = true;
            return true;
        }
    } else {
        // Brute-force mode: Check tên file hợp lệ
        // Đã sửa: dùng std::all_of
        if (name_len > 3 && std::all_of(entry, entry + name_len, [](unsigned char c){ return c >= 32 && c <= 126; })) {
             std::lock_guard<std::mutex> lock(PRINT_MUTEX);
             std::cout << "\n[!!!] POTENTIAL KEY FOUND [!!!]" << std::endl;
             std::cout << "      Identifier: " << identifier << std::endl;
             std::cout << "      Filename:   " << std::string((char*)entry, name_len) << std::endl;
             // Không set FOUND=true để nó chạy tiếp các case khác
             return true;
        }
    }
    return false;
}

void worker(int start_idx) {
    std::string s = "aaaaaa";
    s[0] = CHARSET[start_idx];
    for (int i1=0; i1<CHARSET_LEN; ++i1) { s[1] = CHARSET[i1];
    for (int i2=0; i2<CHARSET_LEN; ++i2) { s[2] = CHARSET[i2];
    for (int i3=0; i3<CHARSET_LEN; ++i3) { s[3] = CHARSET[i3];
    for (int i4=0; i4<CHARSET_LEN; ++i4) { s[4] = CHARSET[i4];
    for (int i5=0; i5<CHARSET_LEN; ++i5) { s[5] = CHARSET[i5];
        if (FOUND) return;
        if (check_identifier(s)) return;
    }}}}}
}

int main() {
    std::ifstream file(FILENAME, std::ios::binary | std::ios::ate);
    if (!file) { std::cerr << "File not found!" << std::endl; return 1; }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    FILE_DATA.resize(size);
    if (!file.read((char*)FILE_DATA.data(), size)) return 1;

    SALT.insert(SALT.end(), FILE_DATA.begin() + 8, FILE_DATA.begin() + 34);
    std::memcpy(&FAT_OFFSET, &FILE_DATA[0x22], 8);
    std::memcpy(&DATA_OFFSET, &FILE_DATA[0x2E], 8);

    std::cout << "[*] Starting brute-force..." << std::endl;
    
    // Check thủ công trước
    if(check_identifier("ks2025")) return 0;

    std::vector<std::thread> threads;
    for (int i = 0; i < CHARSET_LEN; ++i) {
        threads.emplace_back(worker, i);
    }
    for (auto& t : threads) t.join();

    if (!FOUND) std::cout << "[-] Not found." << std::endl;
    return 0;
}