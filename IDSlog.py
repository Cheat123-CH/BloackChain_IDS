import json
import hashlib
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
    # remove stored hash before recomputing
    if "hash" in block_copy:
        del block_copy["hash"]
    return hashlib.sha256(
        json.dumps(block_copy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

def verify_chain_file(path):
    with open(path, "r") as f:
        chain = json.load(f)

    # FIX: detect structure
    if isinstance(chain, dict):
        if "chain" in chain:
            chain = chain["chain"]
        else:
            chain = [chain[key] for key in sorted(chain, key=lambda x: int(x))]

    ok = True
    for i in range(1, len(chain)):
        prev = chain[i - 1]
        curr = chain[i]

        if curr["previous_hash"] != hash_block(prev):
            print(f"{RED}[!] Block {i} invalid previous_hash{RESET}")
            ok = False

    print(YELLOW + "Chain verification: " + str(ok) + RESET)
    return chain, ok 

def pretty_print_chain(chain):
    # If chain is a dict -> convert to list
    if isinstance(chain, dict):
        if "chain" in chain:
            chain = chain["chain"]
        else:
            chain = [chain[k] for k in sorted(chain, key=lambda x: int(x))]

    for b in chain:
        
        # FIX: sometimes the block is wrapped in a list
        if isinstance(b, list):
            if len(b) > 0:
                b = b[0]
            else:
                continue

        if not isinstance(b, dict):
            continue  # skip invalid items

        index = b.get("index", "N/A")
        ts = b.get("timestamp", "N/A")

        print(YELLOW + f"Date/time:  {ts} ---" + RESET)

if __name__ == "__main__":
    chain = verify_chain_file("chain.json")
    pretty_print_chain(chain)