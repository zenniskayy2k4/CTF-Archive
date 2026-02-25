#include <iostream>
#include <vector>
#include <thread>
#include <atomic>

// Cấu hình tìm kiếm
uint32_t TARGET_1 = 0; // Sẽ nhập từ tham số
uint32_t TARGET_2 = 0; // Sẽ nhập từ tham số
bool HAS_TARGET_2 = false;
std::atomic<bool> FOUND(false);

// Constants MT19937
const uint32_t N = 624;
const uint32_t M = 397;
const uint32_t MATRIX_A = 0x9908B0DF;
const uint32_t UPPER_MASK = 0x80000000;
const uint32_t LOWER_MASK = 0x7FFFFFFF;

void check_range(uint32_t start, uint32_t end) {
    // Cấp phát mảng mt một lần để tái sử dụng, tránh alloc liên tục
    std::vector<uint32_t> mt(N); 

    for (uint32_t seed = start; seed < end; ++seed) {
        if (FOUND) return;

        // 1. Init MT19937 (Chỉ cần chạy đến M+1 là đủ để tính số đầu tiên)
        // Optimization: Không cần init hết 624 số nếu chỉ check số đầu
        mt[0] = seed;
        for (int i = 1; i <= M + 2; ++i) {
            mt[i] = (1812433253U * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i);
        }

        // 2. Twist & Temper số đầu tiên (index 0)
        // y = (mt[0] & U) | (mt[1] & L)
        uint32_t y = (mt[0] & UPPER_MASK) | (mt[1] & LOWER_MASK);
        // mt[0] new = mt[M] ^ (y >> 1) ^ mag01
        uint32_t mag01 = (y & 1) ? MATRIX_A : 0;
        uint32_t mt0_new = mt[M] ^ (y >> 1) ^ mag01;

        // Tempering
        y = mt0_new;
        y ^= (y >> 11);
        y ^= ((y << 7) & 0x9D2C5680);
        y ^= ((y << 15) & 0xEFC60000);
        y ^= (y >> 18);

        // Check Target 1 (20 bit)
        if ((y & 0xFFFFF) == TARGET_1) {
            // Nếu khớp số 1, ta mới tính tiếp để khớp số 2 (chậm hơn nhưng ít khi xảy ra)
            
            // Cần init nốt phần còn lại nếu chưa đủ
            for (int i = M + 3; i < N; ++i) {
                 mt[i] = (1812433253U * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i);
            }
            
            // Twist số thứ 2 (index 1)
            // y = (mt[1] & U) | (mt[2] & L)
            uint32_t y2 = (mt[1] & UPPER_MASK) | (mt[2] & LOWER_MASK);
            uint32_t mag01_2 = (y2 & 1) ? MATRIX_A : 0;
            // mt[1] new = mt[1+M] ... (Cẩn thận index: (1+397) = 398)
            uint32_t mt1_new = mt[1 + M] ^ (y2 >> 1) ^ mag01_2;
            
            y2 = mt1_new;
            y2 ^= (y2 >> 11);
            y2 ^= ((y2 << 7) & 0x9D2C5680);
            y2 ^= ((y2 << 15) & 0xEFC60000);
            y2 ^= (y2 >> 18);

            if ((y2 & 0xFFFFF) == TARGET_2) {
                FOUND = true;
                std::cout << "\n[+] FOUND SEED: " << seed << std::endl;
                return;
            }
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: ./crack <target1> <target2>" << std::endl;
        return 1;
    }

    TARGET_1 = std::stoul(argv[1]);
    TARGET_2 = std::stoul(argv[2]);

    unsigned int num_threads = std::thread::hardware_concurrency();
    std::cout << "[*] Running bruteforce with " << num_threads << " threads..." << std::endl;
    std::cout << "[*] Looking for Target1: " << TARGET_1 << ", Target2: " << TARGET_2 << std::endl;

    std::vector<std::thread> threads;
    uint32_t range = 4294967295U / num_threads;
    
    for (unsigned int i = 0; i < num_threads; ++i) {
        uint32_t start = i * range;
        uint32_t end = (i == num_threads - 1) ? 4294967295U : (i + 1) * range;
        threads.emplace_back(check_range, start, end);
    }

    for (auto& t : threads) {
        t.join();
    }

    return 0;
}