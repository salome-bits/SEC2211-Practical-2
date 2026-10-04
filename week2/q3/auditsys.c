/* SEC2211 Practical 2 - Q3: Security-event logging system.
 *
 *   Producer A --\
 *   Producer B ---+--> [POSIX shared memory event buffer] --> Logger --> audit.log
 *   Producer C --/        guarded by [POSIX named semaphore]     |
 *                                                                +--(pipe)--> Parent (stats)
 *
 * IPC mechanisms used (and why):
 *   1. POSIX shared memory (shm_open/mmap): many writers, one reader, no copying
 *      through the kernel per event; deliberately gives us SHARED STATE to attack.
 *   2. POSIX named semaphore (sem_open) used as a binary mutex: protects the shared
 *      'head' index + slot write (the critical section).
 *   3. Anonymous pipe: Logger -> Parent final statistics (simple one-way, ordered).
 *
 * Usage: ./auditsys <safe|unsafe> [events_per_producer=500] [window_us=1]
 *                   [pace_us=0] [logfile=audit.log]
 *   window_us : artificial delay INSIDE the critical section (widens the race so
 *               it shows reliably; set 0 to see that the bug exists without it)
 *   pace_us   : delay between events (slows the system so you can run ps/lsof/strace)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#define SHM_NAME   "/sec2211_audit_shm"
#define SEM_NAME   "/sec2211_audit_mutex"
#define MAX_EVENTS 8192
#define EV_LEN     96
#define NPROD      3
#define MAX_PER    2000

struct shared {
    int  head;                 /* SHARED RESOURCE #1: index of next free slot   */
    int  done;                 /* parent sets when all producers have finished  */
    char slot[MAX_EVENTS][EV_LEN];   /* SHARED RESOURCE #2: event records       */
};

static const char *TYPES[] = { "LOGIN_SUCCESS", "LOGIN_FAILED", "FILE_ACCESS",
                               "INVALID_REQUEST", "SECURITY_ALERT" };
#define NTYPES 5

static int  safe_mode, per_prod, window_us, pace_us;
static const char *logpath = "audit.log";
static struct shared *sh;
static sem_t *mutex;

static void die(const char *m) { perror(m); exit(1); }

/* ------------------------------------------------------------------ producer */
static void producer(int id)
{
    char name[16], who = 'A' + id;
    snprintf(name, sizeof name, "producer-%c", who);
    prctl(PR_SET_NAME, name);

    for (int seq = 0; seq < per_prod; seq++) {
        /* Producer C raises a SECURITY_ALERT every 10th event (the record we
         * most care about losing); others cycle through the first four types. */
        const char *type = (id == 2 && seq % 10 == 0) ? "SECURITY_ALERT"
                                                       : TYPES[(seq + id) % 4];
        char msg[EV_LEN];
        snprintf(msg, sizeof msg, "ts=%ld prod=%c seq=%d type=%s",
                 (long)time(NULL), who, seq, type);

        if (safe_mode) while (sem_wait(mutex) == -1 && errno == EINTR) ;

        /* ============== CRITICAL SECTION (protects head + slot[head]) ======= */
        int idx = sh->head;                          /* CHECK: read shared index */
        if (window_us) usleep(window_us);            /* race window (demo only)  */
        if (idx >= 0 && idx < MAX_EVENTS) {          /* bounds check             */
            memset(sh->slot[idx], 0, EV_LEN);
            memcpy(sh->slot[idx], msg, strlen(msg)); /* USE: write the record    */
            __atomic_store_n(&sh->head, idx + 1, __ATOMIC_RELEASE); /* publish   */
        }
        /* ==================================================================== */

        if (safe_mode) sem_post(mutex);
        if (pace_us) usleep(pace_us);
    }
    _exit(0);
}

/* -------------------------------------------------------------------- logger */
static void logger(int pipe_wr)
{
    prctl(PR_SET_NAME, "audit-logger");
    /* 0640: owner rw, group r, others none -> ordinary users cannot read/alter */
    int fd = open(logpath, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0640);
    if (fd < 0) die("logger open audit.log");

    int rd = 0, written = 0, regress = 0;
    for (;;) {
        int h = __atomic_load_n(&sh->head, __ATOMIC_ACQUIRE);
        if (h < rd) { regress++; usleep(200); continue; }    /* head moved BACKWARDS */
        if (rd < h) {
            for (; rd < h; rd++) {
                size_t len = strnlen(sh->slot[rd], EV_LEN - 1);
                if (len == 0) continue;                      /* empty slot: nothing */
                char line[EV_LEN + 2];
                memcpy(line, sh->slot[rd], len);
                line[len] = '\n';
                ssize_t w = write(fd, line, len + 1);
                if (w != (ssize_t)(len + 1)) die("logger write");
                written++;
            }
        } else if (__atomic_load_n(&sh->done, __ATOMIC_ACQUIRE)) {
            break;                                           /* drained and finished */
        } else usleep(1000);
    }
    fsync(fd);
    close(fd);
    char buf[64];
    int n = snprintf(buf, sizeof buf, "logged=%d regress=%d head=%d\n",
                     written, regress, sh->head);
    write(pipe_wr, buf, n);
    close(pipe_wr);
    _exit(0);
}

/* ------------------------------------------------------------ verification */
static void verify(int expected_alerts)
{
    FILE *f = fopen(logpath, "r");
    if (!f) die("verify fopen");
    static unsigned char seen[NPROD][MAX_PER];
    char line[256]; int lines = 0, dup = 0, bad = 0, alerts = 0;
    while (fgets(line, sizeof line, f)) {
        char p, type[32]; int seq; lines++;
        if (sscanf(line, "ts=%*d prod=%c seq=%d type=%31s", &p, &seq, type) != 3 ||
            p < 'A' || p >= 'A' + NPROD || seq < 0 || seq >= per_prod) { bad++; continue; }
        if (seen[p - 'A'][seq]++) dup++;
        if (!strcmp(type, "SECURITY_ALERT")) alerts++;
    }
    fclose(f);
    int missing = 0;
    for (int p = 0; p < NPROD; p++)
        for (int s = 0; s < per_prod; s++) if (!seen[p][s]) missing++;
    printf("RESULT mode=%s expected=%d lines_in_log=%d missing=%d duplicates=%d "
           "corrupt=%d alerts_expected=%d alerts_logged=%d\n",
           safe_mode ? "SAFE" : "UNSAFE", NPROD * per_prod, lines, missing, dup, bad,
           expected_alerts, alerts);
}

int main(int argc, char **argv)
{
    if (argc < 2 || (strcmp(argv[1], "safe") && strcmp(argv[1], "unsafe"))) {
        fprintf(stderr, "usage: %s <safe|unsafe> [events] [window_us] [pace_us] [logfile]\n", argv[0]);
        return 2;
    }
    safe_mode = !strcmp(argv[1], "safe");
    per_prod  = argc > 2 ? atoi(argv[2]) : 500;
    window_us = argc > 3 ? atoi(argv[3]) : 1;
    pace_us   = argc > 4 ? atoi(argv[4]) : 0;
    if (argc > 5) logpath = argv[5];
    if (per_prod < 1 || per_prod > MAX_PER || NPROD * per_prod > MAX_EVENTS) {
        fprintf(stderr, "events_per_producer must be 1..%d\n", MAX_PER); return 2;
    }

    shm_unlink(SHM_NAME); sem_unlink(SEM_NAME);               /* clean stale state */
    int fd = shm_open(SHM_NAME, O_CREAT | O_EXCL | O_RDWR, 0600);   /* owner only */
    if (fd < 0) die("shm_open");
    if (ftruncate(fd, sizeof *sh) < 0) die("ftruncate");
    sh = mmap(NULL, sizeof *sh, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (sh == MAP_FAILED) die("mmap");
    memset(sh, 0, sizeof *sh);
    if (safe_mode) {
        mutex = sem_open(SEM_NAME, O_CREAT | O_EXCL, 0600, 1);      /* binary semaphore */
        if (mutex == SEM_FAILED) die("sem_open");
    }

    int pfd[2];
    if (pipe(pfd) < 0) die("pipe");

    printf("[parent pid=%d] mode=%s events/producer=%d window_us=%d pace_us=%d log=%s\n",
           getpid(), argv[1], per_prod, window_us, pace_us, logpath);

    pid_t lp = fork();
    if (lp == 0) { close(pfd[0]); logger(pfd[1]); }
    printf("[parent] logger   pid=%d\n", lp);

    pid_t pp[NPROD];
    for (int i = 0; i < NPROD; i++) {
        pp[i] = fork();
        if (pp[i] == 0) { close(pfd[0]); close(pfd[1]); producer(i); }
        printf("[parent] producer-%c pid=%d\n", 'A' + i, pp[i]);
    }
    close(pfd[1]);
    fflush(stdout);

    for (int i = 0; i < NPROD; i++) waitpid(pp[i], NULL, 0);
    __atomic_store_n(&sh->done, 1, __ATOMIC_RELEASE);
    waitpid(lp, NULL, 0);

    char stats[128] = {0};
    read(pfd[0], stats, sizeof stats - 1);
    printf("[logger stats via pipe] %s", stats);

    int alerts_expected = (per_prod + 9) / 10;
    verify(alerts_expected);

    munmap(sh, sizeof *sh); close(fd); shm_unlink(SHM_NAME);
    if (safe_mode) { sem_close(mutex); sem_unlink(SEM_NAME); }
    return 0;
}
