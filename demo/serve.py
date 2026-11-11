#serves the benign clone page on localhost:8000 for the demo, nothing else
import http.server
import os

os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "clone"))
http.server.ThreadingHTTPServer(("127.0.0.1", 8000), http.server.SimpleHTTPRequestHandler).serve_forever()
