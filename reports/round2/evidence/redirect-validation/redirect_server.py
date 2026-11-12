#!/usr/bin/env python3
"""Server redirect lokal untuk bukti R2-02 (scope enforcement).

Menyajikan tiga rute:
  /same     -> 302 ke /final            (host sama, harus DIIKUTI)
  /cross    -> 302 ke http://127.0.0.2:PORT/final  (host lain, harus DITOLAK)
  /down     -> 302 ke http://...        (downgrade https->http; diuji unit)
  /final    -> 200 "FINAL-OK"

Dipakai oleh reports/round2/evidence/redirect-validation/run.sh.
Tidak ada koneksi keluar: semua alamat loopback.
"""
import http.server
import socketserver
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18099
OTHER = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.2"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/same":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/cross":
            self.send_response(302)
            self.send_header("Location", f"http://{OTHER}:{PORT}/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/port":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{PORT + 1}/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"FINAL-OK"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002
        pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    srv = Server(("127.0.0.1", PORT), Handler)
    print(f"listening 127.0.0.1:{PORT}", flush=True)
    srv.serve_forever()
