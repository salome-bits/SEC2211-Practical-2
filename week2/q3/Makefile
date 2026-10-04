CFLAGS=-Wall -Wextra -O1
all: auditsys toctou
auditsys: auditsys.c ; gcc $(CFLAGS) $< -o $@ -lrt -pthread
toctou: toctou.c ; gcc $(CFLAGS) $< -o $@
clean: ; rm -rf auditsys toctou toctou_dir audit.log
