#!/bin/bash
# Usage: ./run_tests.sh v1|v2   -> starts that server on a test port, runs malformed_tests.py
V=${1:-v1}; PORT=5051
./server_$V $PORT > server_$V.log 2>&1 &
PID=$!
sleep 0.5
python3 malformed_tests.py $PID $PORT | tee results_$V.txt
kill $PID 2>/dev/null; wait $PID 2>/dev/null; RC=$?
echo; echo "server exit status: $RC (134 = abort/SIGABRT, 139 = SIGSEGV, 143 = SIGTERM by us)"
echo "--- server log tail ---"; tail -15 server_$V.log
