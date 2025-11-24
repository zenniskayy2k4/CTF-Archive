#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/seccomp.h>
#include <syscall.h>
#include <sys/prctl.h>

#define CODE_LEN 4096

void read_flag(int *len, char **buf) {
  int fd = open("./flag.txt", O_RDONLY);
  struct stat st;
  fstat(fd, &st);
  *len = st.st_size;
  *buf = mmap(NULL, *len, PROT_READ, MAP_SHARED, fd, 0);
}

void disable_syscalls(void) {
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  struct sock_filter filter_prog[] = {
      { BPF_RET,  0,  0, SECCOMP_RET_KILL_PROCESS },
  };
  struct sock_fprog filter = { 1, filter_prog };
  syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &filter);
}


void *read_code(void) {
  void *code = mmap(NULL, CODE_LEN, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_ANON, -1, 0);
  read(0, code, CODE_LEN);
  return code;
}

int main() {
  setbuf(stdout, NULL);
  char *flag;
  int flag_len;
  read_flag(&flag_len, &flag);

  puts("I will execute whatever code you want... as long as it has no syscalls :)");
  puts("Here is the address of the flag good luck");
  printf("%p\n", flag);

  void *code = read_code();

  disable_syscalls();

  goto *code;

  return 0; 
}
