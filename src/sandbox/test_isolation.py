import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from content_features import SANDBOX_FLAGS, IMAGE

#run with: python src/sandbox/test_isolation.py   (needs the docker image built first)
#starts two throwaway servers on the docker bridge address. the container is told that
#only :8765 is its target, so :9999 on the very same ip must stay unreachable
ADDR = "172.17.0.1"
leaks = []


class Ok(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


class Leak(Ok):
    def do_GET(self):
        leaks.append(self.path)
        super().do_GET()


for port, handler in [(8765, Ok), (9999, Leak)]:
    threading.Thread(target=HTTPServer((ADDR, port), handler).serve_forever, daemon=True).start()

TARGET = ["-e", f"TARGET_IPS={ADDR}", "-e", "TARGET_PORT=8765"]

#every blocked test prints an explicit BLOCKED, so a container that never started
#(and printed nothing) cant pass by accident
CONN = """
import socket
try:
    s = socket.socket(); s.settimeout(5); s.connect(("{host}", {port})); print("CONNECTED")
except Exception:
    print("BLOCKED")
"""
DNS = """
import socket
try:
    print(socket.gethostbyname("example.com"))
except Exception:
    print("BLOCKED")
"""


def run(cmd):
    # same flags as the real fetch, just a different command inside the container
    full = ["docker", "run", "--rm"] + SANDBOX_FLAGS + TARGET + [IMAGE] + cmd
    p = subprocess.run(full, capture_output=True, text=True, timeout=40)
    return (p.stdout + p.stderr).strip()


def conn(host, port):
    return ["python3", "-c", CONN.format(host=host, port=port)]


tests = [
    ("runs as non-root", ["id", "-u"], lambda o: o.isdigit() and o != "0"),
    ("no capabilities left", ["grep", "-E", "CapEff|CapBnd|NoNewPrivs", "/proc/self/status"],
     lambda o: "CapEff:\t0000000000000000" in o and "CapBnd:\t0000000000000000" in o
     and "NoNewPrivs:\t1" in o),
    ("cannot change firewall", ["sh", "-c", "iptables -F && echo CHANGED || echo DENIED"],
     lambda o: o.startswith("DENIED")),
    ("target ip:port reachable", conn(ADDR, 8765), lambda o: o == "CONNECTED"),
    ("other port, same ip blocked", conn(ADDR, 9999), lambda o: o == "BLOCKED"),
    ("internet by ip blocked", conn("1.1.1.1", 80), lambda o: o == "BLOCKED"),
    ("internet 443 blocked", conn("8.8.8.8", 443), lambda o: o == "BLOCKED"),
    ("dns blocked", ["python3", "-c", DNS], lambda o: o == "BLOCKED"),
    ("root fs read-only", ["sh", "-c", "touch /app/x && echo WROTE || echo DENIED"],
     lambda o: o.startswith("DENIED")),
    ("ipv6 disabled", ["cat", "/proc/sys/net/ipv6/conf/all/disable_ipv6"], lambda o: o == "1"),
]

ok = True
for name, cmd, check in tests:
    try:
        out = run(cmd)
    except subprocess.TimeoutExpired:
        out = "TIMEOUT"
    passed = check(out)
    ok &= passed
    print(f"{'PASS' if passed else 'FAIL'}  {name:30s} {out[:80].replace(chr(10), ' | ')}")

print(f"requests that reached the off-limits port: {len(leaks)}")
ok &= not leaks
print("ALL PASSED" if ok else "SOME FAILED")
sys.exit(0 if ok else 1)
