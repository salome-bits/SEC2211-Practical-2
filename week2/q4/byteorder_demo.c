/* SEC2211 Q4.5: host vs network byte order. Run: ./byteorder_demo [port] */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>

static void dump(const char *label, const void *p, size_t n)
{
    const unsigned char *b = p;
    printf("  %-22s bytes in memory (low addr -> high): ", label);
    for (size_t i = 0; i < n; i++) printf("%02x ", b[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    uint16_t port = argc > 1 ? (uint16_t)atoi(argv[1]) : 5050;
    uint32_t big  = 0x0A0B0C0D;
    uint16_t one  = 1;
    printf("This host is %s-endian\n", *(unsigned char *)&one ? "LITTLE" : "BIG");

    printf("\nPort %u = 0x%04x\n", port, port);
    dump("host order (uint16)", &port, 2);
    uint16_t np = htons(port);
    dump("htons(port)", &np, 2);
    printf("  value read back as integer after htons: 0x%04x (bytes swapped on little-endian)\n", np);
    uint16_t back = ntohs(np);
    printf("  ntohs(htons(port)) = %u -> round trip %s\n", back, back == port ? "OK" : "FAILED");

    printf("\n32-bit value 0x%08x\n", big);
    dump("host order (uint32)", &big, 4);
    uint32_t nl = htonl(big);
    dump("htonl(value)", &nl, 4);
    printf("  ntohl(htonl(v)) = 0x%08x\n", ntohl(nl));

    printf("\nNetwork byte order is BIG-endian: most significant byte first on the wire.\n"
           "Forgetting htons() on sin_port would make the server listen on port %u instead of %u.\n",
           ntohs(port), port);
    return 0;
}
