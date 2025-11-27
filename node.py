
import socketserver
import json
import hashlib
import time
import threading
from typing import List
import os

CHAIN_FILE = "chain.json"
HOST = "0.0.0.0"
PORT = 9000

# Must match gateway secret
GATEWAY_NODE_SECRET = b"supersecret_gateway_node"


def hash_block(block: dict) -> str:
    # produce SHA256 over canonical JSON
    b = json.dumps(block, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b).hexdigest()

class SimpleChain:
    def __init__(self):
        self.lock = threading.Lock()
        self.chain: List[dict] = []
        self._load_or_create()

    def _load_or_create(self):
        if os.path.exists(CHAIN_FILE):
            with open(CHAIN_FILE, "r") as f:
                self.chain = json.load(f)
                print(f"[Node] Loaded chain with {len(self.chain)} blocks from {CHAIN_FILE}")
        else:
            # create genesis block
            genesis = {
                "index": 0,
                "timestamp": time.time(),
                "data": {"genesis": True},
                "prev_hash": "0" * 64,
            }
            genesis["hash"] = hash_block(genesis)
            self.chain = [genesis]
            self._persist()
            print("[Node] Created genesis block")

    def _persist(self):
        with open(CHAIN_FILE, "w") as f:
            json.dump(self.chain, f, indent=2, sort_keys=True)

    def add_block(self, data: dict) -> dict:
        with self.lock:
            index = len(self.chain)
            prev_hash = self.chain[-1]["hash"]
            block = {
                "index": index,
                "timestamp": time.time(),
                "data": data,
                "prev_hash": prev_hash,
            }
            block["hash"] = hash_block(block)
            self.chain.append(block)
            self._persist()
            return block

    def verify_chain(self) -> dict:
        with self.lock:
            for i in range(1, len(self.chain)):
                curr = self.chain[i]
                prev = self.chain[i - 1]
                if curr["prev_hash"] != prev["hash"]:
                    return {"valid": False, "reason": f"prev_hash mismatch at index {i}"}
                if hash_block(curr) != curr["hash"]:
                    return {"valid": False, "reason": f"hash mismatch at index {i}"}
            return {"valid": True, "length": len(self.chain)}


chain = SimpleChain()

class NodeTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        raw = self.rfile.readline().strip()
        if not raw:
            return
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception as e:
            self.wfile.write(json.dumps({"status": "error", "message": f"invalid json: {e}"}).encode("utf-8"))
            return

        # Verify gateway HMAC
        gateway_hmac = payload.get("gateway_hmac")
        payload_copy = dict(payload)
        if "gateway_hmac" in payload_copy:
            del payload_copy["gateway_hmac"]
        calc = hashlib.sha256(json.dumps(payload_copy, sort_keys=True).encode("utf-8") + GATEWAY_NODE_SECRET).hexdigest()
        # The gateway used HMAC properly (sha256 HMAC) — but easier: verify with same function as gateway
        # To be strict, we should compute HMAC. Let's compute real HMAC:
        import hmac
        import hashlib as _hashlib
        calc_hmac = hmac.new(GATEWAY_NODE_SECRET, json.dumps(payload_copy, sort_keys=True).encode("utf-8"), _hashlib.sha256).hexdigest()

        if gateway_hmac != calc_hmac:
            self.wfile.write(json.dumps({"status": "error", "message": "gateway_hmac invalid"}).encode("utf-8"))
            print("[Node] Rejected payload with invalid gateway_hmac")
            return

        # Append to blockchain
        block = chain.add_block(payload)
        print(f"[Node] Accepted block index {block['index']}, from gateway (stored).")
        self.wfile.write(json.dumps({"status": "ok", "block_index": block["index"], "hash": block["hash"]}).encode("utf-8"))


if __name__ == "__main__":
    print(f"[Node] Starting node server on {HOST}:{PORT}")
    server = socketserver.ThreadingTCPServer((HOST, PORT), NodeTCPHandler)
    server.serve_forever()
