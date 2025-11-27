
import socket
import threading
import json
import hmac
import hashlib
import time

# Configuration
GATEWAY_HOST = "0.0.0.0"
GATEWAY_PORT = 8000

NODE_HOST = "127.0.0.1"
NODE_PORT = 9000

# Shared secret between gateway and node for HMAC authentication
GATEWAY_NODE_SECRET = b"supersecret_gateway_node"

# Optionally a list of known sensors' secrets
SENSOR_SECRETS = {
    "sensor-1": b"sensor1-secret",
    "sensor-2": b"sensor2-secret",
}

def compute_hmac(secret: bytes, data_bytes: bytes) -> str:
    return hmac.new(secret, data_bytes, hashlib.sha256).hexdigest()


def forward_to_node(block_payload: dict) -> dict:
    """
    Connect to node and send a JSON payload.
    Returns node response (dict) or error dict.
    """
    payload_bytes = json.dumps(block_payload).encode("utf-8")
    try:
        with socket.create_connection((NODE_HOST, NODE_PORT), timeout=5) as s:
            s.sendall(payload_bytes + b"\n")
            # read response
            resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
            if not resp:
                return {"status": "error", "message": "no response from node"}
            return json.loads(resp.decode("utf-8"))
    except Exception as e:
        return {"status": "error", "message": f"failed to connect to node: {e}"}


def handle_sensor_connection(conn, addr):
    with conn:
        data = b""
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                # accept newline-delimited JSON
                if b"\n" in data:
                    break
            if not data:
                return
            raw_json = data.strip().decode("utf-8")
            alert = json.loads(raw_json)
        except Exception as e:
            print("[Gateway] Invalid data from", addr, e)
            return

        sensor_id = alert.get("sensor_id", "unknown")
        sensor_secret = SENSOR_SECRETS.get(sensor_id)

        if sensor_secret:
            # verify sensor HMAC if included
            recv_hmac = alert.get("sensor_hmac")
            alert_copy = dict(alert)
            if "sensor_hmac" in alert_copy:
                del alert_copy["sensor_hmac"]
            computed = compute_hmac(sensor_secret, json.dumps(alert_copy, sort_keys=True).encode("utf-8"))
            if recv_hmac != computed:
                print(f"[Gateway] HMAC mismatch for {sensor_id} from {addr}")
                conn.sendall(json.dumps({"status": "error", "message": "hmac mismatch"}).encode("utf-8"))
                return
        else:
            print(f"[Gateway] REJECTED unknown sensor '{sensor_id}'")
            conn.sendall(json.dumps({"status": "error", "message": "untrusted sensor"}).encode("utf-8"))
            return

        # Create block payload to forward to node
        block = {
            "timestamp": time.time(),
            "sensor_payload": alert,
            "gateway_ts": time.time(),
        }

        # Sign the block with gateway-node shared secret
        block_bytes = json.dumps(block, sort_keys=True).encode("utf-8")
        block_hmac = compute_hmac(GATEWAY_NODE_SECRET, block_bytes)
        block["gateway_hmac"] = block_hmac

        print(f"[Gateway] Forwarding alert from {sensor_id} to node...")
        resp = forward_to_node(block)
        conn.sendall(json.dumps(resp).encode("utf-8"))

def start_gateway():
    print(f"[Gateway] Starting gateway on {GATEWAY_HOST}:{GATEWAY_PORT}, forwarding to node {NODE_HOST}:{NODE_PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((GATEWAY_HOST, GATEWAY_PORT))
        s.listen(5)
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_sensor_connection, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    start_gateway()
