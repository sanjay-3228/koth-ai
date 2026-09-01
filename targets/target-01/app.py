from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = b"KOTH Target 01\n"
        elif self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /admin\n"
        elif self.path == "/admin":
            body = b"Training admin endpoint\n"
        else:
            body = b"Not found\n"

        self.send_response(200 if self.path in ["/", "/robots.txt", "/admin"] else 404)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
