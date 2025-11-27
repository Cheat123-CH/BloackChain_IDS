
import json
import hashlib
import time
from typing import Dict, Any

# ANSI Colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"


def load_chain(path: str):
    with open(path, "r") as f:
        return json.load(f)


def hash_block(block):
    block_copy = dict(block)
    del block_copy["hash"]
    return hashlib.sha256(
        json.dumps(block_copy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def verify_chain_file(path: str) -> dict:
    """
    Verify chain file on disk and return dict: {valid:bool, reason:..., length:N}
    Adds COLOR output for mismatch and success
    """
    chain = load_chain(path)

    for i in range(1, len(chain)):
        curr = chain[i]
        prev = chain[i - 1]

        # Check prev_hash
        if curr["prev_hash"] != prev["hash"]:
            print(RED + f"[ERROR] prev_hash mismatch at index {i}" + RESET)
            return {"valid": False, "reason": f"prev_hash mismatch at index {i}", "index": i}

        # Check block hash
        if hash_block(curr) != curr["hash"]:
            print(RED + f"[ERROR] hash mismatch at index {i}" + RESET)
            return {"valid": False, "reason": f"hash mismatch at index {i}", "index": i}

    print(GREEN + "[OK] Blockchain verified — no tampering detected." + RESET)
    return {"valid": True, "length": len(chain)}


def pretty_print_chain(chain):
    """
    Pretty printing each block with yellow labels and normal text.
    """
    for b in chain:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(b["timestamp"]))

        print(YELLOW + f"--- Block {b['index']} @ {ts} ---" + RESET)
        print(f"Prev: {b['prev_hash']}")
        print(f"Hash: {b.get('hash')}")
        print("Data:")
        try:
            print(json.dumps(b["data"], indent=2, sort_keys=True))
        except Exception:
            print(repr(b["data"]))
        print("")


if __name__ == "__main__":
    chain = load_chain("chain.json")
    verify_chain_file("chain.json")
    pretty_print_chain(chain)
