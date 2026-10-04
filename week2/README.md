# SEC 2211 Practical Assignment 2 — Week 2 (Q3 & Q4)

Environment: Linux (Ubuntu/Kali), `gcc`, `python3`. Optional tools: `strace lsof psmisc(pstree) iproute2(ss) netcat tcpdump`.
Everything runs on localhost only (server binds 127.0.0.1).

```
week2/
├── q3/  auditsys.c  toctou.c  Makefile
└── q4/  server.c  client.c  byteorder_demo.c  malformed_tests.py  run_tests.sh  Makefile
```

Clone → Build → Run:
```bash
cd week2/q3 && make && cd ../q4 && make
```

---------------------------------------------------------------------
## Q3 — IPC security-event logging system

Architecture (Task 3.1/3.2):
```
producer-A ─┐
producer-B ─┼─► [POSIX shared memory: head + slot[]] ─► audit-logger ─► audit.log (0640)
producer-C ─┘        guarded by POSIX semaphore (safe mode)     └─ pipe ─► parent (stats)
```
| Mechanism | Why chosen |
|---|---|
| Shared memory | many writers → one reader without per-event kernel copies; creates the shared state we need to attack |
| Named semaphore (value 1) | binary mutex protecting `head` and `slot[head]` |
| Pipe | one-way, ordered final statistics logger → parent |

`./auditsys <safe|unsafe> [events=500] [window_us=1] [pace_us=0] [logfile]`

### 3.3 Observe (use `pace_us` to slow it down, e.g. 20000 ≈ 30 s run)
```bash
./auditsys safe 500 1 20000 &
ps -eLf | grep -E 'auditsys|producer|logger'     # names set with prctl(PR_SET_NAME)
pstree -p $(pgrep -o auditsys)                   # parent -> logger + 3 producers
ls -l /dev/shm                                   # sec2211_audit_shm, sem.sec2211_audit_mutex
lsof -p $(pgrep audit-logger)                    # audit.log fd, pipe fd, /dev/shm mapping
cat /proc/$(pgrep audit-logger)/maps | grep sec2211   # shared mapping visible in the address space
sudo strace -f -p $(pgrep -o auditsys)           # futex / write / nanosleep activity
```
Connect each line to the diagram: same shm mapping in 4 processes, audit.log open only in the logger, pipe shared parent↔logger.

### 3.4 Race condition
- **Shared resource:** `sh->head` (next free slot) and `slot[]`.
- **Prediction:** two producers read the same `head`, both write the same slot, both store `head+1` → one event overwritten (lost); `head` can even move backwards.
- Run repeatedly: `for i in $(seq 10); do ./auditsys unsafe 500 1 | grep RESULT; done`
- Sample result from my machine (yours will differ — it is nondeterministic):
  `RESULT mode=UNSAFE expected=1500 lines_in_log=503 missing=997 ... alerts_expected=50 alerts_logged=26`
  → **half the SECURITY_ALERT records vanished** (security consequence: attacker activity disappears from the audit trail).
- `window_us` only widens the window. Try `./auditsys unsafe 500 0`: on my machine it rarely/never failed, but the bug is still there — absence of failure ≠ correctness. Try it on more load (`stress`/more events) and explain.

### 3.5 Fix
- **Protected resource:** `head` + the slot being written. **Critical section:** read `head` → write slot → publish `head+1` (marked in `auditsys.c`).
- `./auditsys safe 500 1` → `RESULT mode=SAFE expected=1500 lines_in_log=1500 missing=0 duplicates=0 ... alerts_logged=50`
- Present before/after tables from 10 runs each. Remove the `sem_wait/sem_post` live if asked → failure returns.
- Lecturer questions to prepare: why can the logger read `head` without the lock? (it only needs a consistent published index: producer uses release-store, logger acquire-load.) What if a producer dies holding the semaphore? (deadlock — robust mutexes/timeouts are the production answer.)

### 3.6 TOCTOU (`toctou.c`, only touches `./toctou_dir`)
```bash
./toctou vuln     # access() then open(): race lets the write land in protected.txt
./toctou safe     # open(O_CREAT|O_EXCL|O_NOFOLLOW) + fstat on the fd: protected file stays intact
```
CHECK = `access(W_OK)`; RACE WINDOW = 20 µs sleep; CHANGE = another process atomically `rename()`s a symlink over `app.log`; USE = `open()` follows the symlink. Fix: no separate check — one atomic open that fails on symlinks, then validate the *descriptor* (not the name). Also try `strace -f ./toctou vuln` to see `access` then `openat`.

---------------------------------------------------------------------
## Q4 — TCP client/server

Protocol: `STATUS`, `EVENT <TYPE> <detail>`, `COUNT`, `QUIT` (no command execution).
`server_v1` = original (weak, on purpose). `server_v2` = hardened. Same `server.c`, `-DHARDENED`.
```bash
./server_v2 5050 &              # prints listening_fd, port in host order and wire bytes
./client -c STATUS              # one-shot
./client                        # interactive (type lines)
```
### 4.3 Descriptors
Server startup prints `listening_fd=3`; each accept prints `client_fd=4`, etc. `accept()` returns a *new* fd because the listening socket must keep existing to accept further connections, while each connected socket is a separate kernel object (own peer address, buffers). Show with `ls -l /proc/<pid>/fd` and `lsof -p <pid>` while a client is connected (use `./client` interactive and leave it open). Tie back to Q1: same descriptor table → open file description → resource model.

### 4.4 Blocking
```bash
./server_v1 5050 &  PID=$!
ps -o pid,stat,pcpu,wchan:20,cmd -p $PID      # STAT=S, %CPU≈0, wchan shows socket wait
strace -p $PID                                # stuck at accept(3, ...
./client -c STATUS                            # strace now shows accept returning 4
```
Blocking = process is *sleeping in the kernel* (state S, 0% CPU) until an event wakes it; a busy loop would show state R and ~100% CPU.

### 4.5 Byte order
`./byteorder_demo 5050` → host bytes `ba 13`, wire bytes `13 ba`. `server` also prints both. Confirm on the wire: `sudo tcpdump -i lo -X port 5050` and look at the port bytes in the TCP header.

### 4.6 Observe
```bash
ss -ltnp | grep 5050        # LISTEN, 127.0.0.1:5050, pid, fd
ss -tnp  | grep 5050        # ESTAB / CLOSE-WAIT connections
lsof -i :5050
strace -f -e trace=network,read,write,close ./server_v2 5050
printf 'STATUS\n' | nc 127.0.0.1 5050
```

### 4.7 Security testing: original → improvement → verification
```bash
./run_tests.sh v1     # results_v1.txt
./run_tests.sh v2     # results_v2.txt
```
| Test | v1 (original) | v2 (hardened) |
|---|---|---|
| unknown command / bad event type | accepted with `OK` | `ERR 400` / `ERR 422` |
| embedded newline / control chars | forged-looking lines written to server log (log injection) | each line validated separately; non-printable rejected |
| 100 000 bytes, no newline | silently truncated at 1023 bytes | `ERR 413`, connection closed |
| connect then close (×5) | **fd leak**: server fd count grows 4→9 (`CLOSE_WAIT` in `ss`) | no leak (count stays 4) |
| idle client holds connection | **blocks all other clients** indefinitely | 5 s receive timeout, then other client served |
| 200-byte EVENT detail | `*** buffer overflow detected ***` → **server aborts (exit 134)**, DoS | `ERR 413`, server continues |

Fixes in v2: line framing over `recv()` loop (TCP is a byte stream, not messages), `MAX_LINE`/`MAX_DETAIL` limits, command + type whitelist, printable-only check, `SO_RCVTIMEO`, `MSG_NOSIGNAL`/ignore `SIGPIPE`, always `close(cfd)`, loopback-only bind, per-connection request cap.

Known remaining limit (say this in the report, it is Week 3 / Q6): v2 is still **iterative** — one client at a time, so a slow client can still delay others for up to the timeout; no TLS/authentication.

---------------------------------------------------------------------
## Suggested Git history (assignment wants visible progression)
```
Q3: shared-memory logger with producers (unsafe)
Q3: add observation notes and verification of audit.log
Q3: add semaphore mutual exclusion + before/after results
Q3: add TOCTOU demo and fix
Q4: initial iterative server
Q4: add client
Q4: byte-order demo
Q4: malformed-input test harness (v1 results)
Q4: hardened v2: framing, validation, timeout, fd cleanup
Q4: v2 verification results
```
Put evidence (strace/lsof/ss/tcpdump outputs, `results_*.txt`) under `evidence/week2/`.
