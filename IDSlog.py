import json
import hashlib

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

def hash_block(block: dict) -> str:
    block_copy = dict(block)
    block_copy.pop("hash", None)

    return hashlib.sha256(
        json.dumps(block_copy, sort_keys=True, separators=(",", ":"))
        .encode("utf-8")
    ).hexdigest()


def verify_chain_file(path: str):
    with open(path, "r", encoding="utf-8") as f:
        chain = json.load(f)

    if isinstance(chain, dict):
        chain = chain.get("chain", chain)

    tampered = False

    for i in range(len(chain)):
        block = chain[i]

        stored_hash = block.get("hash")
        computed_hash = hash_block(block)

        if stored_hash != computed_hash:
            print(f"{RED}[!] Block {i} HASH MISMATCH (DATA TAMPERED){RESET}")
            tampered = True
        if i > 0:
            prev = chain[i - 1]
            if block.get("previous_hash") != hash_block(prev):
                print(f"{RED}[!] Block {i} previous_hash INVALID{RESET}")
                tampered = True

    if not tampered:
        print(GREEN + "[✓] Log integrity OK – No tamper detected" + RESET)
    else:
        print(RED + "[✗] Log tampering detected!" + RESET)

    return chain, not tampered

def pretty_print_chain(chain):
    for b in chain:
        if isinstance(b, list):
            b = b[0] if b else None
        if not isinstance(b, dict):
            continue

        ts = b.get("timestamp", "N/A")
        index = b.get("index", "N/A")

    print(YELLOW + f"Time: {ts}" + RESET)


if __name__ == "__main__":
    chain, ok = verify_chain_file("chain.json")
    pretty_print_chain(chain)
