"""Public-key pinning (pin_sha256 / PIN_SHA256) of the command-line clients.

knock.py, knock.sh and knock.ps1 each run against local HTTPS servers with
self-signed RSA and EC certificates: with the right pin the request arrives;
with a wrong one the client stops after the handshake and the server sees no
request. A pin next to an http:// server URL is refused. The pin itself is
checked against the one openssl computes. A client whose tools are missing
(bash + curl, PowerShell) is skipped.

    python -m unittest discover -s client/tests -v
"""

import base64
import hashlib
import http.server
import importlib.util
import json
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

CLIENT = Path(__file__).resolve().parent.parent
OPENSSL = shutil.which("openssl")

_spec = importlib.util.spec_from_file_location("knock", CLIENT / "knock.py")
knock = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(knock)

WRONG_PIN = base64.b64encode(hashlib.sha256(b"another key").digest()).decode()
KEYS = {"rsa": ["-newkey", "rsa:2048"],
        "ec": ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"]}


def make_cert(directory, key_args):
    """Self-signed certificate for 127.0.0.1; returns (cert, key, pin by openssl)."""
    cert, key = str(Path(directory) / "cert.pem"), str(Path(directory) / "key.pem")
    subprocess.run([OPENSSL, "req", "-x509", "-nodes", "-days", "1", *key_args,
                    "-keyout", key, "-out", cert, "-subj", "/CN=127.0.0.1"],
                   check=True, capture_output=True)
    pem = subprocess.run([OPENSSL, "x509", "-in", cert, "-pubkey", "-noout"],
                         check=True, capture_output=True, text=True).stdout
    spki = base64.b64decode("".join(l for l in pem.splitlines() if "-----" not in l))
    return cert, key, base64.b64encode(hashlib.sha256(spki).digest()).decode()


def cert_der(cert):
    return ssl.PEM_cert_to_DER_cert(Path(cert).read_text())


class Handler(http.server.BaseHTTPRequestHandler):
    seen = []  # (method, path, Authorization) of every request that arrived

    def _reply(self):
        Handler.seen.append((self.command, self.path, self.headers.get("Authorization", "")))
        body = json.dumps({"ok": True, "ip": "127.0.0.1", "message": "IP registered"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _reply

    def log_message(self, *args):
        pass


class Server(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass  # a client that stops after the handshake (a wrong pin) drops the connection


@unittest.skipUnless(OPENSSL, "openssl not found")
class PinTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.servers = {}  # key type -> (url, pin)
        cls.httpds = []
        for name, args in KEYS.items():
            d = Path(cls.tmp.name) / name
            d.mkdir()
            cert, key, pin = make_cert(d, args)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            httpd = Server(("127.0.0.1", 0), Handler)
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            cls.httpds.append(httpd)
            cls.servers[name] = (f"https://127.0.0.1:{httpd.server_address[1]}", pin, cert)

    @classmethod
    def tearDownClass(cls):
        for httpd in cls.httpds:
            httpd.shutdown()
            httpd.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        Handler.seen.clear()

    def write(self, name, text):
        path = Path(self.tmp.name) / name
        path.write_text(text, encoding="utf-8")
        return str(path)

    def yaml_config(self, url, pin):
        return self.write("client.yaml", f'server_url: "{url}"\nusername: "alice"\n'
                                         f'secret: "s3cret"\nverify_ssl: true\npin_sha256: "{pin}"\n')

    def sh_config(self, url, pin):
        return self.write("client.conf", f"SERVER_URL={url}\nUSERNAME=alice\n"
                                         f"SECRET=s3cret\nPIN_SHA256={pin}\n")

    # -- the pin itself ---------------------------------------------------- #

    def test_pin_matches_openssl(self):
        for name, (_, pin, cert) in self.servers.items():
            with self.subTest(key=name):
                self.assertEqual(knock.spki_sha256(cert_der(cert)), pin)
        with tempfile.TemporaryDirectory() as d:
            try:
                cert, _, pin = make_cert(d, ["-newkey", "ed25519"])
            except subprocess.CalledProcessError:
                self.skipTest("this openssl cannot make ed25519 keys")
            self.assertEqual(knock.spki_sha256(cert_der(cert)), pin)

    # -- knock.py ------------------------------------------------------------ #

    def test_knock_py(self):
        for name, (url, pin, _) in self.servers.items():
            with self.subTest(key=name):
                Handler.seen.clear()
                cfg = knock.load_config(self.yaml_config(url, pin))
                result = knock.knock(cfg["server_url"], "alice", "s3cret", pin=cfg["pin_sha256"])
                self.assertTrue(result.get("ok"), result)
                self.assertEqual(len(Handler.seen), 1)
                method, path, auth = Handler.seen[0]
                self.assertEqual((method, path), ("POST", "/api/knock"))
                self.assertTrue(auth.startswith("HMAC-SHA256 alice:"), auth)
                self.assertTrue(knock.status(url, "alice", "s3cret", pin=pin).get("ok"))

                Handler.seen.clear()
                # verify_ssl false must not weaken a configured pin.
                bad = knock.knock(url, "alice", "s3cret", verify_ssl=False, pin=WRONG_PIN)
                self.assertFalse(bad.get("ok"))
                self.assertIn("does not match pin_sha256", bad["error"])
                self.assertIn(pin, bad["error"])
                self.assertEqual(Handler.seen, [])

    def test_knock_py_rejects_malformed_pin(self):
        url, pin, _ = self.servers["rsa"]
        with self.assertRaises(SystemExit):
            knock.load_config(self.yaml_config(url, "sha256//" + pin))

    # -- knock.sh ------------------------------------------------------------ #

    def run_sh(self, url, pin, *args):
        return subprocess.run(["bash", str(CLIENT / "knock.sh"), *args], capture_output=True,
                              text=True, env={**os.environ, "KNOCK_CONFIG": self.sh_config(url, pin)},
                              timeout=60)

    @unittest.skipIf(os.name == "nt" or not (shutil.which("bash") and shutil.which("curl")),
                     "needs bash and curl")
    def test_knock_sh(self):
        for name, (url, pin, _) in self.servers.items():
            with self.subTest(key=name):
                Handler.seen.clear()
                ok = self.run_sh(url, pin)
                self.assertEqual(ok.returncode, 0, ok.stderr)
                self.assertTrue(json.loads(ok.stdout)["ok"])
                self.assertEqual([s[:2] for s in Handler.seen], [("POST", "/api/knock")])

                Handler.seen.clear()
                bad = self.run_sh(url, WRONG_PIN, "--insecure")  # --insecure must not weaken it
                self.assertNotEqual(bad.returncode, 0)
                self.assertIn("pinned", bad.stderr)
                self.assertEqual(Handler.seen, [])

    @unittest.skipIf(os.name == "nt" or not shutil.which("bash"), "needs bash")
    def test_knock_sh_refuses_old_curl(self):
        # Before 7.49 some TLS backends accepted --pinnedpubkey without checking it.
        url, pin, _ = self.servers["rsa"]
        fake = Path(self.tmp.name) / "old-curl"
        fake.mkdir(exist_ok=True)
        (fake / "curl").write_text("#!/bin/sh\necho 'curl 7.48.0 (x86_64-pc-linux-gnu) libcurl/7.48.0'\n")
        (fake / "curl").chmod(0o755)
        r = subprocess.run(["bash", str(CLIENT / "knock.sh")], capture_output=True, text=True, timeout=60,
                           env={**os.environ, "KNOCK_CONFIG": self.sh_config(url, pin),
                                "PATH": f"{fake}{os.pathsep}{os.environ['PATH']}"})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("needs curl 7.49 or later (found: 7.48.0)", r.stdout)
        self.assertEqual(Handler.seen, [])

    # -- knock.ps1 ----------------------------------------------------------- #

    def shells(self):
        shells = ["pwsh"] + (["powershell"] if os.name == "nt" else [])
        found = [s for s in shells if shutil.which(s)]
        if not found:
            self.skipTest("no PowerShell")
        return found

    def run_ps1(self, shell, url, pin):
        return subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-File", str(CLIENT / "knock.ps1"), "-Config", self.yaml_config(url, pin)],
            capture_output=True, text=True, timeout=120)

    def test_knock_ps1(self):
        for shell in self.shells():
            for name, (url, pin, _) in self.servers.items():
                with self.subTest(shell=shell, key=name):
                    Handler.seen.clear()
                    ok = self.run_ps1(shell, url, pin)
                    self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
                    self.assertIn("[OK]", ok.stdout)
                    self.assertEqual([s[:2] for s in Handler.seen], [("POST", "/api/knock")])

                    Handler.seen.clear()
                    bad = self.run_ps1(shell, url, WRONG_PIN)
                    self.assertEqual(bad.returncode, 1, bad.stdout + bad.stderr)
                    self.assertIn("does not match pin_sha256", bad.stdout)
                    self.assertIn(pin, bad.stdout)
                    self.assertEqual(Handler.seen, [])

    # -- a pin needs https --------------------------------------------------- #

    def test_pin_needs_https(self):
        # Nothing listens there: each client must refuse before connecting.
        url, pin = "http://127.0.0.1:9", self.servers["rsa"][1]
        result = knock.knock(url, "alice", "s3cret", pin=pin)
        self.assertIn("needs an https:// server_url", result.get("error", ""))
        if os.name != "nt" and shutil.which("bash") and shutil.which("curl"):
            sh = self.run_sh(url, pin)
            self.assertNotEqual(sh.returncode, 0)
            self.assertIn("needs an https:// SERVER_URL", sh.stdout)
        for shell in [s for s in ["pwsh"] + (["powershell"] if os.name == "nt" else []) if shutil.which(s)]:
            ps = self.run_ps1(shell, url, pin)
            self.assertEqual(ps.returncode, 1, ps.stdout + ps.stderr)
            self.assertIn("needs an https:// server_url", ps.stdout)


if __name__ == "__main__":
    unittest.main()
