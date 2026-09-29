#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main() {
    printf("=====================================================\n");
    printf("       SEC2211 SYSTEM INSPECTION UTILITY (PID: %d)   \n", getpid());
    printf("=====================================================\n\n");

    // 1. OPEN FIRST FILE & PREDICT DESCRIPTOR
    printf("[STEP 1] Opening 'sample.txt'...\n");
    printf("  Prediction: Slots 0, 1, 2 are taken. Returned FD will be 3.\n");
    int fd1 = open("sample.txt", O_RDWR | O_CREAT, 0644);
    if (fd1 == -1) {
        perror("  Error opening sample.txt");
    } else {
        printf("  Actual Result: Allocated FD = %d\n\n", fd1);
    }

    // 2. OPEN A SECOND FILE & PREDICT DESCRIPTOR
    printf("[STEP 2] Opening 'second.txt' without changing existing code...\n");
    printf("  Prediction: Slots 0, 1, 2, 3 are taken. Returned FD will be 4.\n");
    int fd2 = open("second.txt", O_RDWR | O_CREAT, 0644);
    if (fd2 == -1) {
        perror("  Error opening second.txt");
    } else {
        printf("  Actual Result: Allocated FD = %d\n\n", fd2);
    }

    // 3. CHANGE CURRENT FILE OFFSET
    printf("[STEP 3] Changing file offset using lseek()...\n");
    off_t old_offset = lseek(fd1, 0, SEEK_CUR);
    off_t new_offset = lseek(fd1, 10, SEEK_SET);
    printf("  Offset moved from %ld bytes to %ld bytes.\n\n", old_offset, new_offset);

    // 4. EXPLAIN WHY AN OPERATION FAILED (DAC Permission Failure Demo)
    printf("[STEP 4] Attempting to open a non-existent or restricted file...\n");
    int fail_fd = open("/root/secret_admin_file.txt", O_RDONLY);
    if (fail_fd == -1) {
        printf("  Operation Failed as expected!\n");
        printf("  Returned FD: %d\n", fail_fd);
        printf("  Kernel Error Code (errno %d): %s\n", errno, strerror(errno));
        printf("  Explanation: Kernel DAC check rejected request at trust boundary;\n");
        printf("               NO File Descriptor slot was allocated.\n\n");
    }

    // 5. REDIRECT STDOUT (FD 1) TO A LOG FILE
    printf("[STEP 5] Redirecting stdout (FD 1) to 'output.log'...\n");
    printf("  Notice: Text AFTER this line will NOT appear on screen!\n");
    fflush(stdout); // Flush buffer before duplicating descriptor

    int log_fd = open("output.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    dup2(log_fd, 1); // Unplugs terminal stdout (1) and plugs into output.log
    close(log_fd);   // Clean up extra descriptor reference

    printf("This text was written via redirected FD 1 straight into output.log!\n");
    fflush(stdout);

    // 6. PROCESS PAUSE FOR LIVE INSPECTION (/proc, strace, memory maps)
    // We write to stderr (FD 2) because FD 1 is redirected to file!
    fprintf(stderr, "\n=====================================================\n");
    fprintf(stderr, " [PAUSED] Process PID: %d is sitting at getchar().\n", getpid());
    fprintf(stderr, " Run inspection commands in Terminal Tab 2 now.\n");
    fprintf(stderr, " Press [ENTER] in this terminal when finished to exit.\n");
    fprintf(stderr, "=====================================================\n");

    getchar(); // Keeps process alive for /proc examination

    // Clean up
    close(fd1);
    close(fd2);
    return 0;
}
