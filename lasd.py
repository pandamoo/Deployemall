import http.server
import socketserver
import os
import threading
from datetime import datetime

# --- CONFIGURATION ---
PORT = 8080
PAYLOAD_PATH = "session.elf"
MAX_THREADS = 60  # Adjust based on your VPS CPU/RAM

# Simple Rate Limiting (IP-based)
request_history = {}
RATE_LIMIT_SECONDS = 2  # Minimum seconds between requests from the same IP

class ThreadedHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Handle each request in a separate thread."""
    daemon_threads = True
    allow_reuse_address = True
    # Limits the number of threads to prevent system exhaustion
    process_request_thread_limit = MAX_THREADS

class SecureHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Custom logging with timestamps
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {self.client_address[0]} - {args[1]}")

    def is_spaming(self):
        client_ip = self.client_address[0]
        now = datetime.now().timestamp()
        if client_ip in request_history:
            last_request = request_history[client_ip]
            if now - last_request < RATE_LIMIT_SECONDS:
                return True
        request_history[client_ip] = now
        return False

    def do_GET(self):
        # 1. Anti-Spam Check
        if self.is_spaming():
            self.send_error(429, "Too Many Requests")
            return

        # 2. Hardcoded File Delivery (Anti-Traversal)
        if not os.path.exists(PAYLOAD_PATH):
            self.send_error(404, "Payload Not Found")
            return

        try:
            with open(PAYLOAD_PATH, 'rb') as f:
                content = f.read()

            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()

            # 3. Broken Pipe Shield
            # We write in chunks to better catch disconnects without crashing the thread
            chunk_size = 1024 * 16 # 16KB chunks
            for i in range(0, len(content), chunk_size):
                self.wfile.write(content[i:i+chunk_size])

        except (ConnectionResetError, BrokenPipeError):
            # This is where the "Broken Pipe" usually happens. 
            # We catch it and let the thread die gracefully.
            pass
        except Exception as e:
            print(f"[!] Unexpected Error: {e}")

if __name__ == "__main__":
    if not os.path.exists(PAYLOAD_PATH):
        print(f"[!] Warning: {PAYLOAD_PATH} not found in current directory!")
        
    with ThreadedHTTPServer(("", PORT), SecureHandler) as server:
        print(f"[*] Robust Server Active on port {PORT}")
        print(f"[*] Thread Pool Limit: {MAX_THREADS}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[!] Shutting down server...")
            server.shutdown()
