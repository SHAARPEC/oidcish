"""Connection module."""
import http.server
import json
import socket
from socketserver import TCPServer
from urllib.parse import urlparse


def port_is_free(port: int) -> bool:
    """Check whether port is free to access."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        return not sock.connect_ex(("localhost", port)) == 0


class SigninRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Handler class for receiving a sign-in redirection."""

    def _set_headers(self):
        """Set default headers."""
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()

    def do_GET(self) -> None:
        """Dummy get handler only needs to be available for a single request."""
        path = urlparse(self.path).path

        self._set_headers()
        self.wfile.write(
            json.dumps({"signin_recieved": path == "/oauth2/callback"}).encode(("utf8"))
        )

    # Silent server.
    def log_message(self, format, *args):
        return


class ReuseAddrTCPServer(TCPServer):
    """TCP server which allows reuse of sockets."""

    allow_reuse_address: bool = True
    timeout: float = 1.0
