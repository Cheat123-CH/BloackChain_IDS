import json
import hashlib

# ANSI Colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"



def hash_block(block):
    block_copy = dict(block)
    block_copy.pop("hash", None)
    return hashlib.sha256(
        json.dumps(block_copy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def verify_chain_file(path):
    with open(path, "r") as f:
        chain = json.load(f)

    if isinstance(chain, dict) and "chain" in chain:
        chain = chain["chain"]

    ok = True

    for i in range(1, len(chain)):
        if chain[i]["previous_hash"] != hash_block(chain[i - 1]):
            print(f"{RED}[!] Block {i} hash mismatch{RESET}")
            ok = False

    # ================== RESULT ==================
    if ok:
        print(GREEN + "Log Integrity: VERIFIED" + RESET)
        print(GREEN + "No tampering detected" + RESET)
    else:
        print(RED + "Log Integrity: FAILED" + RESET)
        print(RED + "LOG TAMPERING DETECTED" + RESET)

    return chain, ok


# def pretty_print_chain(chain):
#     print(YELLOW + f"Date/time: {block.get('timestamp', 'N/A')}" + RESET)


if __name__ == "__main__":
    chain = verify_chain_file("chain.json") 
    # pretty_print_chain(chain)
