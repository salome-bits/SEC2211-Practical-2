#!/usr/bin/env python3
"""SEC2211 Q4.7 - malformed/oversized input tests against YOUR OWN lab server on localhost.
Usage: malformed_tests.py <server_pid> [port=5050]"""
import socket, sys, time, os

PID = int(sys.argv[1]); PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5050

def alive():
    return os.path.exists(f"/proc/{PID}")

def fds():
    try: return len(os.listdir(f"/proc/{PID}/fd"))
    except FileNotFoundError: return -1

def talk(data, wait=2.0, shut=False):
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=wait)
        s.sendall(data)
        if shut: s.shutdown(socket.SHUT_WR)
        s.settimeout(wait)
        try: r = s.recv(4096)
        except socket.timeout: r = b"<no reply within %.0fs>" % wait
        s.close()
        return r
    except Exception as e:
        return f"<exception {type(e).__name__}: {e}>".encode()

def case(name, data, **kw):
    before = fds()
    r = talk(data, **kw)
    time.sleep(0.2)
    print(f"{'-'*70}\nCASE: {name}\n  sent {len(data)} bytes\n  reply: {r[:100]!r}")
    print(f"  server alive: {alive()}   server fd count: {before} -> {fds()}")
    return alive()

print(f"Testing server pid {PID} on 127.0.0.1:{PORT}")
case("valid STATUS", b"STATUS\n")
case("valid EVENT", b"EVENT LOGIN_FAILED user=alice\n")
case("unknown command", b"DELETE EVERYTHING\n")
case("invalid event type", b"EVENT HACKED something\n")
case("log injection (embedded newline)", b"EVENT LOGIN_FAILED x\nEVENT SECURITY_ALERT FORGED-ENTRY\n")
case("control characters", b"EVENT FILE_ACCESS bad\x01\x02\x1b[31mred\n")
case("two requests in one TCP segment", b"COUNT\nSTATUS\n")
case("huge input, no newline (100000 bytes)", b"B" * 100000)
for i in range(5):
    talk(b"", wait=0.5, shut=True)           # connect and close without sending
time.sleep(0.3)
print(f"{'-'*70}\nCASE: 5 connect-then-disconnect clients\n  server fd count now: {fds()}"
      f"  (growth = descriptor leak)")

print(f"{'-'*70}\nCASE: idle client blocks everyone else?")
idle = socket.create_connection(("127.0.0.1", PORT)); t0 = time.time()
r = talk(b"STATUS\n", wait=8.0)
dt = time.time() - t0
print(f"  second client got reply after {dt:.1f}s: {r[:60]!r}")
print("  -> " + ("BLOCKED by idle client (availability weakness)" if dt >= 7.5 else
                 "served once idle client timed out (timeout protects availability)"))
idle.close()

if not case("oversized detail (200 bytes)", b"EVENT LOGIN_FAILED " + b"A" * 200 + b"\n"):
    print("\n>>> SERVER CRASHED on oversized input (denial of service)."); sys.exit(0)
