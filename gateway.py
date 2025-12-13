import socket
import threading
import json
import hmac
import hashlib
import time
from datetime import datetime, UTC

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"
# Gateway configuration
GATEWAY_HOST = "0.0.0.0"
GATEWAY_PORT = 8000

# trust nodes
NODES = [
    ("127.0.0.1", 9000),
    ("127.0.0.1", 9001),
]

# Shared secret between gateway and nodes
GATEWAY_NODE_SECRET = b"Cyber_Gen10"

# trust sensors
SENSOR_SECRETS = {
    "sensor-1": b"sensor1-key",
    "sensor-2": b"sensor2-key",
}

def compute_hmac(secret: bytes, data_bytes: bytes) -> str:
    return hmac.new(secret, data_bytes, hashlib.sha256).hexdigest()

def forward_to_node(block_payload: dict) -> dict:
    """Send payload to all nodes and return the first successful response."""
    payload_bytes = json.dumps(block_payload, sort_keys=True).encode("utf-8") + b"\n"
    responses = []
    for host, port in NODES:
        try:
            with socket.create_connection((host, port), timeout=5) as s:
                s.sendall(payload_bytes)
                resp = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                if resp:
                    responses.append(json.loads(resp.decode("utf-8")))
                print(f"{GREEN}[Gateway] Forwarded alert to node {host}:{port}{RESET}")
        except ConnectionRefusedError:
            # Display message for node error (shut down / offline)
            print(f"{YELLOW}[Gateway] Failed for forwarding !.{host}:{port} (nodes offline){RESET}")
        except Exception:
            # Display message for fail forwarding to node
            print(f"{RED}[Gateway] Failed to forward to node {host}:{port}{RESET}")
    if responses:
        return responses[0]
    return {"status": "error", "message": "no node responded"}

def handle_sensor_connection(conn, addr):
    with conn:
        try:
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\n" in data:
                    break
            if not data:
                return

            alert = json.loads(data.strip().decode("utf-8"))
        except Exception as e:
            print(f"{YELLOW}[Gateway] Invalid data from {addr}: {e}{RESET}")
            return

        sensor_id = alert.get("sensor_id", "unknown")
        sensor_secret = SENSOR_SECRETS.get(sensor_id)

        # Validate sensor HMAC
        if sensor_secret:
            recv_hmac = alert.get("sensor_hmac")
            alert_copy = dict(alert)
            alert_copy.pop("sensor_hmac", None)
            computed_hmac = compute_hmac(
                sensor_secret, json.dumps(alert_copy, sort_keys=True).encode("utf-8")
            )
            if recv_hmac != computed_hmac:
                print(f"[Gateway] HMAC mismatch for {sensor_id} from {addr}")
                conn.sendall(json.dumps({"status": "error", "message": "connection error"}).encode("utf-8"))
                return
        else:
            print(f"{RED}[Gateway] REJECTED unknown sensor '{sensor_id}' from {addr}{RESET}")
            conn.sendall(json.dumps({"status": "error", "message": "block"}).encode("utf-8"))
            return

        # Flatten alert for node and add gateway timestamp
        block = dict(alert)
        block["gateway_ts"] = time.time()

        # Compute gateway HMAC for nodes
        block_copy = dict(block)
        block_hmac = compute_hmac(GATEWAY_NODE_SECRET, json.dumps(block_copy, sort_keys=True).encode("utf-8"))
        block["gateway_hmac"] = block_hmac

        # Forward to nodes
        print(f"[Gateway] Forwarding alert from {sensor_id} to nodes")
        resp = forward_to_node(block)

        # Respond to sensor
        conn.sendall(json.dumps(resp).encode("utf-8"))

def start_gateway():
    print(f"[Gateway] Starting gateway on {GATEWAY_HOST}:{GATEWAY_PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((GATEWAY_HOST, GATEWAY_PORT))
        s.listen(5)
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_sensor_connection, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    start_gateway()
