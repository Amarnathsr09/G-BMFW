import http.server
import socketserver
import ssl
import threading
import httpx

FORWARD_PROXY_PORT = 8888
REVERSE_PROXY_PORT = 8080
SSL_PROXY_PORT = 8443

# === Forward Proxy ===
forward_proxy_stop_event = threading.Event()
forward_proxy_server = None

class ForwardProxyHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Forward Proxy Active")

def run_forward_proxy():
    global forward_proxy_server
    with socketserver.TCPServer(("localhost", FORWARD_PROXY_PORT), ForwardProxyHandler) as httpd:
        forward_proxy_server = httpd
        httpd.timeout = 1
        print(f"[+] Forward Proxy running at http://localhost:{FORWARD_PROXY_PORT}")
        while not forward_proxy_stop_event.is_set():
            httpd.handle_request()
        print("[x] Forward Proxy stopped")

def start_forward_proxy():
    forward_proxy_stop_event.clear()
    threading.Thread(target=run_forward_proxy, daemon=True).start()

def stop_forward_proxy():
    forward_proxy_stop_event.set()
    if forward_proxy_server:
        forward_proxy_server.server_close()
    print("Stopping Forward Proxy...")

# === Reverse Proxy ===
reverse_proxy_stop_event = threading.Event()
reverse_proxy_server = None

class ReverseProxyHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Reverse Proxy Active")

def run_reverse_proxy():
    global reverse_proxy_server
    with socketserver.TCPServer(("localhost", REVERSE_PROXY_PORT), ReverseProxyHandler) as httpd:
        reverse_proxy_server = httpd
        httpd.timeout = 1
        print(f"[+] Reverse Proxy running at http://localhost:{REVERSE_PROXY_PORT}")
        while not reverse_proxy_stop_event.is_set():
            httpd.handle_request()
        print("[x] Reverse Proxy stopped")

def start_reverse_proxy():
    reverse_proxy_stop_event.clear()
    threading.Thread(target=run_reverse_proxy, daemon=True).start()

def stop_reverse_proxy():
    reverse_proxy_stop_event.set()
    if reverse_proxy_server:
        reverse_proxy_server.server_close()
    print("Stopping Reverse Proxy...")

# === SSL Proxy ===
ssl_proxy_stop_event = threading.Event()
ssl_proxy_server = None

def run_ssl_proxy():
    global ssl_proxy_server
    httpd = socketserver.TCPServer(("localhost", SSL_PROXY_PORT), ForwardProxyHandler)
    ssl_socket = ssl.wrap_socket(httpd.socket, certfile="cert.pem", keyfile="key.pem", server_side=True)
    httpd.socket = ssl_socket
    ssl_proxy_server = httpd
    httpd.timeout = 1
    print(f"[+] SSL Proxy running at https://localhost:{SSL_PROXY_PORT}")
    while not ssl_proxy_stop_event.is_set():
        httpd.handle_request()
    print("[x] SSL Proxy stopped")

def start_ssl_proxy():
    ssl_proxy_stop_event.clear()
    threading.Thread(target=run_ssl_proxy, daemon=True).start()

def stop_ssl_proxy():
    ssl_proxy_stop_event.set()
    if ssl_proxy_server:
        ssl_proxy_server.server_close()
    print("Stopping SSL Proxy...")
