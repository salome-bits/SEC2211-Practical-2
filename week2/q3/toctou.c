/* SEC2211 Q3 - TOCTOU demonstration (harmless, runs in ./toctou_dir only).
 * ./toctou vuln : access() then open()  -> race can redirect the write
 * ./toctou safe : open(O_NOFOLLOW|O_EXCL) + fstat on the descriptor
 * "attacker" child repeatedly swaps ./toctou_dir/app.log between a regular
 * file and a symlink to ./toctou_dir/protected.txt (stand-in for a
 * privileged file the victim should never write to). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define DIR_  "toctou_dir"
#define LOG   DIR_ "/app.log"
#define PROT  "protected.txt"          /* symlink target (relative to DIR_) */

static void attacker(void)
{
    /* rename() atomically replaces LOG, so the name is never absent */
    int f = open(DIR_ "/reg.tmp", O_CREAT | O_WRONLY, 0600); if (f >= 0) close(f);
    for (;;) {
        rename(DIR_ "/reg.tmp", LOG);               /* LOG = regular file */
        f = open(DIR_ "/reg.tmp", O_CREAT | O_WRONLY, 0600); if (f >= 0) close(f);
        unlink(DIR_ "/lnk.tmp"); symlink(PROT, DIR_ "/lnk.tmp");
        rename(DIR_ "/lnk.tmp", LOG);               /* LOG = symlink      */
    }
}

static int vulnerable_write(const char *msg)
{
    if (access(LOG, W_OK) != 0) return -1;      /* TIME OF CHECK */
    usleep(20);                                  /* window                */
    int fd = open(LOG, O_WRONLY | O_APPEND);     /* TIME OF USE - follows symlink */
    if (fd < 0) return -1;
    write(fd, msg, strlen(msg));
    close(fd);
    return 0;
}

static int safe_write(const char *msg)
{
    /* One atomic step: refuse symlinks, create exclusively, no separate check */
    int fd = open(LOG, O_WRONLY | O_APPEND | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;                       /* ELOOP/EEXIST => reject */
    struct stat st;                              /* validate the OPEN fd, not the name */
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1) {
        close(fd); return -1;
    }
    write(fd, msg, strlen(msg));
    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    int safe = argc > 1 && !strcmp(argv[1], "safe");
    mkdir(DIR_, 0700);
    int f = open(DIR_ "/" PROT, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    write(f, "ORIGINAL-PROTECTED-CONTENT\n", 27); close(f);

    pid_t atk = fork();
    if (atk == 0) attacker();

    int ok = 0;
    for (int i = 0; i < 20000; i++) {
        int r = safe ? safe_write("VICTIM-LOG-LINE\n") : vulnerable_write("VICTIM-LOG-LINE\n");
        if (r == 0) ok++;
        if (safe) unlink(LOG);                   /* let O_EXCL succeed again */
    }
    kill(atk, SIGKILL); waitpid(atk, NULL, 0);

    char buf[256] = {0};
    f = open(DIR_ "/" PROT, O_RDONLY); read(f, buf, sizeof buf - 1); close(f);
    printf("mode=%s successful writes=%d\n", safe ? "SAFE" : "VULNERABLE", ok);
    if (strstr(buf, "VICTIM-LOG-LINE"))
        puts("!! protected file was MODIFIED via the race (TOCTOU exploited)");
    else
        puts("protected file intact");
    return 0;
}
