#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <stdarg.h>

// Định nghĩa kiểu hàm cho ptrace thật
typedef long (*ptrace_ptr_t)(enum __ptrace_request request, pid_t pid, void *addr, void *data);

long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data) {
    // Nếu là TRACEME (0), lừa chương trình là đã thành công
    if (request == PTRACE_TRACEME) {
        return 0;
    }

    // Với các yêu cầu khác, tìm và gọi hàm ptrace thật từ libc
    static ptrace_ptr_t real_ptrace = NULL;
    if (!real_ptrace) {
        real_ptrace = (ptrace_ptr_t)dlsym(RTLD_NEXT, "ptrace");
    }

    return real_ptrace(request, pid, addr, data);
}