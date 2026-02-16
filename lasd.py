import http.server
import socketserver
import os
import threading
import hmac
from datetime import datetime

# --- CONFIGURATION ---
PORT = 8080
PAYLOAD_PATH = "session.elf"
MAX_THREADS = 60  # Adjust based on your VPS CPU/RAM
TOKEN_ENV_VAR = "DELIVERY_TOKEN"  # expected token is read from environment

class ThreadedHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Handle each request in a separate thread."""
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        # ThreadingMixIn does not have a built-in hard thread limit; enforce one.
        self._thread_limiter = threading.BoundedSemaphore(value=MAX_THREADS)

    def process_request(self, request, client_address):
        self._thread_limiter.acquire()
        try:
            super().process_request(request, client_address)
        except Exception:
            # If the thread cannot be started, release the slot.
            self._thread_limiter.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._thread_limiter.release()

class SecureHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Custom logging with timestamps
        # Avoid printing request headers (may contain secrets).
        # args typically include request line, status code, and size.
        try:
            status = args[1]
        except Exception:
            status = "-"
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {self.client_address[0]} {self.command} {self.path} {status}")

    def _extract_token(self) -> str:
        auth = (self.headers.get("Authorization") or "").strip()
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return (self.headers.get("X-Delivery-Token") or "").strip()

    def _is_authorized(self) -> bool:
        expected = (os.environ.get(TOKEN_ENV_VAR) or "").strip()
        presented = self._extract_token()
        if not expected or not presented:
            return False
        return hmac.compare_digest(presented, expected)

    def _send_unauthorized(self) -> None:
        self.send_response(401)
        self.send_header("WWW-Authenticate", "Bearer")
        self.end_headers()

    def do_GET(self):
        # 1. Token authentication (replaces prior IP rate limiting).
        if not self._is_authorized():
            self._send_unauthorized()
            return

        # 2. Hardcoded File Delivery (Anti-Traversal)
        if not os.path.exists(PAYLOAD_PATH):
            self.send_error(404, "Payload Not Found")
            return

        try:
            size = os.path.getsize(PAYLOAD_PATH)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.end_headers()

            # 3. Broken Pipe Shield
            # Stream in chunks to avoid reading the entire file into memory.
            chunk_size = 1024 * 16  # 16KB chunks
            with open(PAYLOAD_PATH, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    self.wfile.write(chunk)

        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            # This is where the "Broken Pipe" usually happens. 
            # We catch it and let the thread die gracefully.
            pass
        except Exception as e:
            print(f"[!] Unexpected Error: {e}")

    def do_HEAD(self):
        # Mirror GET auth + headers, without the body.
        if not self._is_authorized():
            self._send_unauthorized()
            return
        if not os.path.exists(PAYLOAD_PATH):
            self.send_error(404, "Payload Not Found")
            return
        try:
            size = os.path.getsize(PAYLOAD_PATH)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.end_headers()
        except Exception as e:
            print(f"[!] Unexpected Error: {e}")

if __name__ == "__main__":
    if not os.path.exists(PAYLOAD_PATH):
        print(f"[!] Warning: {PAYLOAD_PATH} not found in current directory!")
    if not (os.environ.get(TOKEN_ENV_VAR) or "").strip():
        raise SystemExit(f"[!] Refusing to start: set {TOKEN_ENV_VAR} in the environment")
        
    with ThreadedHTTPServer(("", PORT), SecureHandler) as server:
        print(f"[*] Robust Server Active on port {PORT}")
        print(f"[*] Thread Pool Limit: {MAX_THREADS}")
        print(f"[*] Auth: send token via Authorization: Bearer <token> or X-Delivery-Token")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[!] Shutting down server...")
            server.shutdown()
