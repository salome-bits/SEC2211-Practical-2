/* secinspect.c - Concise Linux I/O Utility */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    // 1. open() - Get File Descriptor (Task 1.1)
    int fd = open(argv[1], O_RDWR);
    if (fd < 0) { perror("open failed"); return 1; }
    printf("[+] Opened file: %s | Allocated FD: %d\n", argv[1], fd);

    // 2. fstat() - Get Metadata (Task 1.1)
    struct stat st;
    fstat(fd, &st);
    printf("[+] Size: %ld bytes | Permissions: %o\n", st.st_size, st.st_mode & 0777);

    // 3. read() - Read 15 bytes (Task 1.1)
    char buf[32] = {0};
    read(fd, buf, 15);
    printf("[+] Read string: \"%s\"\n", buf);

    // 4. lseek() - Check file offset position (Task 1.1)
    off_t offset = lseek(fd, 0, SEEK_CUR);
    printf("[+] Current Offset after read: %ld\n", offset);

    // 5. dup2() - Redirect stdout (FD 1) to a file (Task 1.3)
    int out_fd = open("redirect.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    dup2(out_fd, STDOUT_FILENO); // FD 1 now points to redirect.log!
    close(out_fd);

    // This printf goes to redirect.log, NOT the terminal screen!
    printf("SUCCESS: stdout redirection via dup2 worked! (FD 1)\n");

    // Clean up
    close(fd);
    return 0;
}
