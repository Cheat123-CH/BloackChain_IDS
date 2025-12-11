#!/usr/bin/env python3
"""
node.py
run: python ./node.py --port

Simple threaded TCP Node that:
- verifies gateway_hmac for incoming JSON transactions
- stores validated transactions
- periodically creates blocks (simple blockchain) to detect tampering
- persists chain to chain.json
- supports chain verification
"""

import socketserver
import json
import hmac
import hashlib
import argparse
import threading
import os
from datetime import datetime, UTC

# Node / Blockchain config
GATEWAY_NODE_SECRET = b"Cyber_Gen10"  # must match gateway secret
CHAIN_FILE = "chain.json"
BLOCK_TX_LIMIT = 4       # create a block every N transactions
MINE_INTERVAL = 15       # seconds: also create block periodically if there are pending txs

lock = threading.Lock()  # protect blockchain data structures


def sha256_hex(s: bytes) -> str:
    return hashlib.sha256(s).hexdigest()


class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions  # list of dicts (already validated)
        self.nonce = nonce
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_content = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "nonce": self.nonce,
        }
        # deterministic serialization
        serialized = json.dumps(block_content, sort_keys=True, separators=(',', ':')).encode("utf-8")
        return sha256_hex(serialized)

    def to_dict(self):
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "nonce": self.nonce,
            "hash": self.hash,
        }

    @staticmethod
    def from_dict(d):
        b = Block(d["index"], d["previous_hash"], d["timestamp"], d["transactions"], d.get("nonce", 0))
        # override computed hash to the stored hash (for loading)
        b.hash = d["hash"]
        return b


class SimpleBlockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.load_chain()
        if not self.chain:
            # create genesis block
            genesis = Block(0, "0" * 64, datetime.utcnow().isoformat() + "Z", [], nonce=0)
            self.chain.append(genesis)
            self.save_chain()

    def last_block(self):
        return self.chain[-1]

    def add_transaction(self, tx_dict):
        """
        tx_dict should be the transaction WITHOUT the gateway_hmac key (we already validated it).
        We'll store the transaction as-is (we recommend storing an original payload + metadata).
        """
        self.pending_transactions.append(tx_dict)
        self.save_chain()  # persist pending txs too (simple approach)

    def create_block(self, nonce=0):
        if not self.pending_transactions:
            return None
        index = len(self.chain)
        previous_hash = self.last_block().hash
        timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        transactions = self.pending_transactions.copy()
        block = Block(index, previous_hash, timestamp, transactions, nonce=nonce)
        # attach block
        self.chain.append(block)
        self.pending_transactions = []
        self.save_chain()
        print(f"[Blockchain] Store block index={block.index} hash={block.hash} txs={len(block.transactions)}")
        return block

    def save_chain(self):
        data = {
            "chain": [b.to_dict() for b in self.chain],
            "pending_transactions": self.pending_transactions,
        }
        with open(CHAIN_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)

    def load_chain(self):
        if not os.path.exists(CHAIN_FILE):
            return
        try:
            with open(CHAIN_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.chain = [Block.from_dict(bd) for bd in data.get("chain", [])]
            self.pending_transactions = data.get("pending_transactions", [])
            print(f"[Blockchain] Loaded chain length={len(self.chain)} pending_tx={len(self.pending_transactions)}")
        except Exception as e:
            print("[Blockchain] Failed to load chain:", e)
            self.chain = []
            self.pending_transactions = []

    def verify_chain(self):
        """
        Verify:
          1. Every block hash is correct for its content
          2. Every block.previous_hash matches the previous block.hash
          3. Every transaction contains a valid gateway_hmac (recompute HMAC)
        Returns (valid: bool, messages: list[str])
        """
        messages = []
        valid = True

        # verify genesis separately
        for i, block in enumerate(self.chain):
            # recompute block.hash based on content (we must ignore the stored 'hash' and recompute)
            recomputed = Block(block.index, block.previous_hash, block.timestamp, block.transactions, block.nonce).compute_hash()
            if recomputed != block.hash:
                valid = False
                messages.append(f"Block {block.index}: invalid hash (stored {block.hash} != recomputed {recomputed})")

            # previous hash check (except genesis)
            if i > 0:
                if block.previous_hash != self.chain[i - 1].hash:
                    valid = False
                    messages.append(f"Block {block.index}: previous_hash mismatch (found {block.previous_hash} expected {self.chain[i - 1].hash})")

            # verify each transaction HMAC (each tx must include original gateway_hmac field)
            for tx_index, tx in enumerate(block.transactions):
                # transaction must have stored gateway_hmac field for verifying
                gw_hmac = tx.get("gateway_hmac")
                if gw_hmac is None:
                    valid = False
                    messages.append(f"Block {block.index} tx {tx_index}: missing gateway_hmac")
                    continue
                # recompute expected hmac from transaction without gateway_hmac
                tx_copy = tx.copy()
                tx_copy.pop("gateway_hmac", None)
                expected = hmac.new(
                    GATEWAY_NODE_SECRET,
                    json.dumps(tx_copy, sort_keys=True).encode("utf-8"),
                    hashlib.sha256
                ).hexdigest()
                if not hmac.compare_digest(gw_hmac, expected):
                    valid = False
                    messages.append(f"Block {block.index} tx {tx_index}: invalid gateway_hmac")

        if valid:
            messages.append("Chain verification: OK")
        return valid, messages


# Global blockchain instance
blockchain = SimpleBlockchain()


def miner_loop(stop_event: threading.Event):
    """
    Periodically create a block if pending transactions exist.
    """
    while not stop_event.wait(MINE_INTERVAL):
        with lock:
            if blockchain.pending_transactions:
                blockchain.create_block()


class NodeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            data = self.request.recv(65536).strip()
            if not data:
                return

            payload = json.loads(data.decode("utf-8"))

            # The sender should include gateway_hmac
            gateway_hmac = payload.get("gateway_hmac")
            if gateway_hmac is None:
                print("[Node] REJECTED: missing gateway_hmac")
                self.request.sendall(json.dumps({"status": "rejected", "reason": "missing gateway_hmac"}).encode("utf-8"))
                return

            # Validate HMAC over the payload without gateway_hmac
            tx_copy = payload.copy()
            tx_copy.pop("gateway_hmac", None)
            expected_hmac = hmac.new(
                GATEWAY_NODE_SECRET,
                json.dumps(tx_copy, sort_keys=True).encode("utf-8"),
                hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(gateway_hmac, expected_hmac):
                print("[Node] REJECTED: invalid gateway_hmac")
                self.request.sendall(json.dumps({"status": "rejected", "reason": "invalid gateway_hmac"}).encode("utf-8"))
                return

            # Accept and store the original payload (including the gateway_hmac so we can re-verify later)
            with lock:
                blockchain.add_transaction(payload)
                # Optionally auto-create a block when pending tx reaches a threshold
                if len(blockchain.pending_transactions) >= BLOCK_TX_LIMIT:
                    blockchain.create_block()
            print("[Node] ALLOWED: transaction accepted")
            response = {
                "status": "ok",
                "chain_length": len(blockchain.chain),
                "pending_transactions": len(blockchain.pending_transactions),
            }
            self.request.sendall(json.dumps(response).encode("utf-8"))

        except Exception as e:
            print("[Node] Error processing payload:", e)
            try:
                self.request.sendall(json.dumps({"status": "error", "message": str(e)}).encode("utf-8"))
            except Exception:
                pass


def run_server(host, port):
    print(f"[Node] Serving at {host}:{port}")
    class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True

    server = ThreadedTCPServer((host, port), NodeHandler)

    stop_event = threading.Event()
    miner_thread = threading.Thread(target=miner_loop, args=(stop_event,), daemon=True)
    miner_thread.start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[Node] Shutting down...")
    finally:
        stop_event.set()
        server.shutdown()
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description="Blockchain Node (tamper-detecting)")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--host", type=str, default="0.0.0.0")
    parser.add_argument("--verify", action="store_true", help="Verify chain and print results then exit")
    args = parser.parse_args()

    if args.verify:
        valid, messages = blockchain.verify_chain()
        print("Verification result:", valid)
        for m in messages:
            print(" -", m)
        return

    run_server(args.host, args.port)


if __name__ == "__main__":
    main()