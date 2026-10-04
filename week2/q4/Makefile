CFLAGS=-Wall -Wextra -O1
all: server_v1 server_v2 client byteorder_demo
server_v1: server.c ; gcc $(CFLAGS) $< -o $@
server_v2: server.c ; gcc $(CFLAGS) -DHARDENED $< -o $@
client: client.c ; gcc $(CFLAGS) $< -o $@
byteorder_demo: byteorder_demo.c ; gcc $(CFLAGS) $< -o $@
clean: ; rm -f server_v1 server_v2 client byteorder_demo *.log results_*.txt
