#define _GNU_SOURCE
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

void setup_seccomp() {
    scmp_filter_ctx ctx;

    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        perror("seccomp_init");
        exit(1);
    }

    int rc = 0;
    rc |= seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(socket), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(connect), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(sendto), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(recvfrom), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(bind), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(accept), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(accept4), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(sendmsg), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(recvmsg), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(getpeername), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(getsockname), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(getsockopt), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(setsockopt), 0);

    if (rc < 0) {
        perror("seccomp_rule_add");
        seccomp_release(ctx);
        exit(1);
    }

    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        seccomp_release(ctx);
        exit(1);
    }

    seccomp_release(ctx);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s /path/to/binary [args...]\n", argv[0]);
        return 1;
    }

    setup_seccomp();

    // Run the target binary with arguments
    execvp(argv[1], &argv[1]);

    // If execvp returns, it's an error
    fprintf(stderr, "Failed to execute '%s': %s\n", argv[1], strerror(errno));
    return 1;
}
