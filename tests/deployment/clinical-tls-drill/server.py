"""Loopback-only synthetic TLS peer for the bounded certificate lifecycle drill."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import ssl
import sys


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"OK"}')

    def log_message(self, *_args):
        pass


def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(sys.argv[1], sys.argv[2])
    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        print(json.dumps({"port": server.server_port}), flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
