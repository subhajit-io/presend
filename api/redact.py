import sys
import os
import json
from http.server import BaseHTTPRequestHandler

# Ensure repository root is on sys.path so presend can be imported
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import presend

class handler(BaseHTTPRequestHandler):
    def send_cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_cors()
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body_bytes = self.rfile.read(length) if length > 0 else b'{}'
        try:
            payload = json.loads(body_bytes.decode('utf-8'))
        except Exception:
            payload = {}

        text = payload.get('text', '')
        overrides = {
            'manualOverrides': payload.get('manualOverrides', {}),
            'labelOverrides': payload.get('labelOverrides', {})
        }

        result = presend.redact(text, overrides=overrides, return_details=True)
        resp_bytes = json.dumps(result).encode('utf-8')

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(resp_bytes)))
        self.send_cors()
        self.end_headers()
        self.wfile.write(resp_bytes)

