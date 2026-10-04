/* SEC2211 Q4 client. Usage: ./client [-H host=127.0.0.1] [-p port=5050] [-c "REQUEST"]
 * With -c: send one request line and print the reply. Without: read request lines
 * from stdin, send each, print each reply (stops if the server closes). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

static int send_all(int fd, const char *s, size_t n)
{
    while (n) {
        ssize_t w = send(fd, s, n, MSG_NOSIGNAL);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        s += w; n -= (size_t)w;
    }
    return 0;
}

/* read one '\n'-terminated reply; returns length, 0 on EOF, -1 on error */
static int recv_line(int fd, char *out, size_t cap)
{
    size_t n = 0;
    while (n + 1 < cap) {
        char c; ssize_t r = recv(fd, &c, 1, 0);
        if (r == 0) return n ? (int)n : 0;
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        out[n++] = c;
        if (c == '\n') break;
    }
    out[n] = '\0';
    return (int)n;
}

int main(int argc, char **argv)
{
    const char *host = "127.0.0.1", *cmd = NULL; int port = 5050, o;
    while ((o = getopt(argc, argv, "H:p:c:")) != -1) {
        if (o == 'H') host = optarg; else if (o == 'p') port = atoi(optarg);
        else if (o == 'c') cmd = optarg; else return 2;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1) { fprintf(stderr, "bad host\n"); return 2; }
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) { perror("connect"); return 1; }
    fprintf(stderr, "[client] connected, fd=%d\n", fd);

    char line[512], reply[512];
    if (cmd) {
        snprintf(line, sizeof line, "%s\n", cmd);
        send_all(fd, line, strlen(line));
        int n = recv_line(fd, reply, sizeof reply);
        if (n > 0) fputs(reply, stdout); else fprintf(stderr, "[client] no reply\n");
    } else {
        while (fgets(line, sizeof line, stdin)) {
            if (send_all(fd, line, strlen(line)) < 0) { perror("send"); break; }
            int n = recv_line(fd, reply, sizeof reply);
            if (n <= 0) { fprintf(stderr, "[client] server closed connection\n"); break; }
            fputs(reply, stdout);
        }
    }
    close(fd);
    return 0;
}
