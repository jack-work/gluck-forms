#!/usr/bin/env python3
"""Shipped entrypoints over an inherited unix socket.

SOCKET_CASES is a JSON list; each case names an entrypoint, its environment,
one request, and the status it must get anonymously and with a hyphen
Remote-User.

  belief     a hyphen Remote-User is believed: the positive control
  underscore Remote_User and remote_user get the anonymous answer
  no tcp     PORT is set but nothing listens on it
  refuse     KWEB_LISTEN=socket with no inherited socket exits nonzero
"""
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ACTIVATE = os.environ["SOCKET_ACTIVATE"]
TMP = tempfile.mkdtemp()
CASES = json.loads(os.environ["SOCKET_CASES"])


def env(case):
    extra = {k: v.replace("@TMP@", TMP) for k, v in case.get("env", {}).items()}
    return {**os.environ, **extra, "KWEB_LISTEN": "socket", "PORT": str(case["port"])}


def call(case, headers, timeout=10):
    c = http.client.HTTPConnection(case.get("host", "x"))
    c.sock = socket.socket(socket.AF_UNIX)
    c.sock.settimeout(timeout)
    c.sock.connect(case["sock"])
    hdrs = dict(headers)
    body = case.get("body")
    if body is not None:
        body = body.encode()
        hdrs["Content-Type"] = "application/json"
    c.request(case.get("method", "GET"), case["path"], body=body, headers=hdrs)
    r = c.getresponse()
    r.read()
    c.close()
    return r.status


def tcp_refused(port):
    s = socket.socket()
    s.settimeout(1)
    try:
        s.connect(("127.0.0.1", port))
        return False
    except ConnectionRefusedError:
        return True
    finally:
        s.close()


class Socket(unittest.TestCase):
    procs = []

    @classmethod
    def setUpClass(cls):
        for case in CASES:
            case["sock"] = os.path.join(TMP, f"{case['name']}.sock")
            e = env(case)
            forward = [f"--setenv={k}" for k in (*case.get("env", {}), "KWEB_LISTEN", "PORT")]
            cls.procs.append(subprocess.Popen(
                [ACTIVATE, "-l", case["sock"], *forward, sys.executable, case["entry"]],
                env=e, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        deadline = time.monotonic() + 30
        for case in CASES:
            while True:
                try:
                    call(case, {}, timeout=2)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise RuntimeError(f"{case['name']} never answered on its socket")
                    time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        for p in cls.procs:
            p.terminate()
            p.wait(timeout=10)

    def test_anonymous_is_refused(self):
        for case in CASES:
            self.assertEqual(call(case, {}), case["anonymous"], case["name"])

    def test_positive_control_hyphen_is_believed(self):
        for case in CASES:
            self.assertEqual(call(case, {"Remote-User": "forged-probe"}), case["believed"], case["name"])

    def test_underscore_forms_are_not_believed(self):
        for case in CASES:
            for header in ("Remote_User", "remote_user"):
                self.assertEqual(call(case, {header: "forged-probe"}), case["anonymous"],
                                 f"{case['name']} {header}")

    def test_no_tcp_listener(self):
        for case in CASES:
            self.assertTrue(tcp_refused(case["port"]), case["name"])


class Refuse(unittest.TestCase):
    def test_no_inherited_socket_means_no_start(self):
        for case in CASES:
            r = subprocess.run([sys.executable, case["entry"]], env=env(case),
                               capture_output=True, text=True, timeout=60)
            self.assertNotEqual(r.returncode, 0, case["name"])
            self.assertIn("refusing to fall back to TCP", r.stderr + r.stdout, case["name"])
            self.assertTrue(tcp_refused(case["port"]), case["name"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
