/* SEC2211 Practical 2 - Q4: TCP security-event / status server (iterative).
 *
 * One source, two builds:
 *   server_v1  (default)   original, deliberately weak implementation
 *   server_v2  (-DHARDENED) improved: framing, validation, limits, timeouts
 *
 * Protocol (text, one request per line, '\n' terminated):
 *   STATUS                    -> OK uptime=<s>s events=<n> load=<simulated>
 *   EVENT <TYPE> <detail>     -> OK id=<n>       TYPE in the whitelist below
 *   COUNT                     -> OK events=<n>
 *   QUIT                      -> OK bye
 * No command execution of any kind is provided.
 *
 * Usage: ./server_v1|server_v2 [port=5050]     (binds 127.0.0.1 only)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define BACKLOG 8
#define MAX_LINE 256          /* v2: longest accepted request line            */
#define MAX_DETAIL 64         /* longest accepted event detail                */
#define MAX_REQS 50           /* v2: requests served per connection           */
#define RECV_TIMEOUT_S 5      /* v2: idle client is dropped after this        */

static int event_count;
static time_t started;

static const char *TYPES[] = { "LOGIN_SUCCESS", "LOGIN_FAILED", "FILE_ACCESS",
                               "INVALID_REQUEST", "SECURITY_ALERT", NULL };

static void say_peer(const struct sockaddr_in *a, int cfd, const char *what)
{
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a->sin_addr, ip, sizeof ip);
    printf("[server] %s client_fd=%d peer=%s:%u (ntohs of wire value 0x%04x)\n",
           what, cfd, ip, ntohs(a->sin_port), a->sin_port);
    fflush(stdout);
}

#ifndef HARDENED
/* ======================================================= v1: ORIGINAL (weak) */
static int serve_v1(int cfd)
{
    char buf[1024];
    ssize_t n = read(cfd, buf, sizeof buf - 1);   /* assumes ONE read = ONE full request */
    if (n <= 0) return -1;                        /* BUG: caller then forgets close(cfd) */
    buf[n] = '\0';
    char resp[128];

    if (strncmp(buf, "STATUS", 6) == 0) {
        snprintf(resp, sizeof resp, "OK uptime=%lds events=%d load=0.%02d\n",
                 (long)(time(NULL) - started), event_count, rand() % 100);
    } else if (strncmp(buf, "EVENT ", 6) == 0) {
        char detail[MAX_DETAIL];
        strcpy(detail, buf + 6);                  /* NO LENGTH CHECK -> stack overflow   */
        event_count++;
        printf("[event %d] %s", event_count, detail);   /* raw -> log injection          */
        fflush(stdout);
        snprintf(resp, sizeof resp, "OK id=%d\n", event_count);
    } else if (strncmp(buf, "COUNT", 5) == 0) {
        snprintf(resp, sizeof resp, "OK events=%d\n", event_count);
    } else {
        snprintf(resp, sizeof resp, "OK\n");      /* accepts anything                    */
    }
    write(cfd, resp, strlen(resp));
    return 0;
}
#else
/* ==================================================== v2: HARDENED (improved) */
static int valid_type(const char *t)
{
    for (int i = 0; TYPES[i]; i++) if (!strcmp(t, TYPES[i])) return 1;
    return 0;
}

static int send_all(int fd, const char *s)
{
    size_t left = strlen(s);
    while (left) {
        ssize_t w = send(fd, s, left, MSG_NOSIGNAL);       /* never raise SIGPIPE */
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        s += w; left -= (size_t)w;
    }
    return 0;
}

/* Handle one validated line; returns 1 to keep the connection, 0 to close. */
static int handle_line(int cfd, char *line)
{
    char resp[128];
    if (!strcmp(line, "STATUS")) {
        snprintf(resp, sizeof resp, "OK uptime=%lds events=%d load=0.%02d\n",
                 (long)(time(NULL) - started), event_count, rand() % 100);
    } else if (!strcmp(line, "COUNT")) {
        snprintf(resp, sizeof resp, "OK events=%d\n", event_count);
    } else if (!strcmp(line, "QUIT")) {
        send_all(cfd, "OK bye\n");
        return 0;
    } else if (!strncmp(line, "EVENT ", 6)) {
        char *type = line + 6, *detail = strchr(type, ' ');
        if (!detail) { send_all(cfd, "ERR 400 usage: EVENT <TYPE> <detail>\n"); return 1; }
        *detail++ = '\0';
        if (!valid_type(type)) { send_all(cfd, "ERR 422 unknown event type\n"); return 1; }
        size_t dl = strlen(detail);
        if (dl == 0 || dl > MAX_DETAIL) { send_all(cfd, "ERR 413 detail length invalid\n"); return 1; }
        for (size_t i = 0; i < dl; i++)
            if (!isprint((unsigned char)detail[i])) { send_all(cfd, "ERR 422 illegal character\n"); return 1; }
        event_count++;
        printf("[event %d] %s %s\n", event_count, type, detail);   /* sanitised */
        fflush(stdout);
        snprintf(resp, sizeof resp, "OK id=%d\n", event_count);
    } else {
        send_all(cfd, "ERR 400 unknown command\n");
        return 1;
    }
    return send_all(cfd, resp) == 0;
}

static void serve_v2(int cfd)
{
    struct timeval tv = { .tv_sec = RECV_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);   /* slow/idle client cap */

    char buf[MAX_LINE + 1];
    size_t used = 0;
    int reqs = 0;
    for (;;) {
        ssize_t n = recv(cfd, buf + used, MAX_LINE - used, 0);
        if (n == 0) return;                                      /* peer closed          */
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                send_all(cfd, "ERR 408 timeout\n");              /* idle too long        */
            return;
        }
        used += (size_t)n;

        char *nl;
        while ((nl = memchr(buf, '\n', used)) != NULL) {         /* FRAMING: split lines */
            size_t len = (size_t)(nl - buf);
            if (len && buf[len - 1] == '\r') len--;
            buf[len] = '\0';
            if (!handle_line(cfd, buf)) return;
            if (++reqs >= MAX_REQS) { send_all(cfd, "ERR 429 request limit\n"); return; }
            size_t consumed = (size_t)(nl - buf) + 1;
            memmove(buf, buf + consumed, used - consumed);
            used -= consumed;
        }
        if (used >= MAX_LINE) {                                  /* LENGTH LIMIT         */
            send_all(cfd, "ERR 413 line too long\n");
            return;
        }
    }
}
#endif

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : 5050;
    if (port < 1 || port > 65535) { fprintf(stderr, "bad port\n"); return 2; }
    started = time(NULL);
#ifdef HARDENED
    signal(SIGPIPE, SIG_IGN);
#endif

    int lfd = socket(AF_INET, SOCK_STREAM, 0);                   /* listening descriptor */
    if (lfd < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);                       /* host -> network order */
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);             /* loopback only         */
    if (bind(lfd, (struct sockaddr *)&addr, sizeof addr) < 0) { perror("bind"); return 1; }
    if (listen(lfd, BACKLOG) < 0) { perror("listen"); return 1; }

    unsigned char *b = (unsigned char *)&addr.sin_port;
    printf("[server pid=%d] %s listening_fd=%d 127.0.0.1:%d | host order 0x%04x, "
           "wire bytes %02x %02x\n", getpid(),
#ifdef HARDENED
           "v2-hardened",
#else
           "v1-original",
#endif
           lfd, port, port, b[0], b[1]);
    fflush(stdout);

    for (;;) {
        struct sockaddr_in peer; socklen_t pl = sizeof peer;
        printf("[server] blocking in accept(listening_fd=%d) ...\n", lfd);
        fflush(stdout);
        int cfd = accept(lfd, (struct sockaddr *)&peer, &pl);    /* BLOCKS here          */
        if (cfd < 0) { if (errno == EINTR) continue; perror("accept"); continue; }
        say_peer(&peer, cfd, "accepted");
#ifdef HARDENED
        serve_v2(cfd);
        close(cfd);
#else
        if (serve_v1(cfd) < 0) continue;     /* descriptor LEAK on empty/failed read */
        close(cfd);
#endif
    }
}
