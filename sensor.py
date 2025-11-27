
import socket
import json
import sys
import time
import hmac
import hashlib
import random

GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 8000

# Should match gateway sensor secrets (for demo)
SENSOR_SECRETS = {
    "sensor-1": b"sensor1-secret",
    "sensor-2": b"sensor2-secret",
}
ATTACK_TYPES = [
    "PORT_SCAN",
    "BRUTE_FORCE",
    "SQL_INJECTION",
    "XSS_ATTACK",
    "RANSOMWARE",
    "MALWARE_TRAFFIC",
    "DNS_TUNNELING",
    "DDOS",
    "ARP_SPOOFING",
    "BOTNET_C2"
]


def compute_hmac(secret: bytes, data_bytes: bytes) -> str:
    return hmac.new(secret, data_bytes, hashlib.sha256).hexdigest()


def make_alert(sensor_id: str):
    alert = {
        "sensor_id": sensor_id,
        "alert_id": f"{sensor_id}-{int(time.time())}-{random.randint(0,9999)}",
        "type": random.choice(ATTACK_TYPES),
        "src_ip": "192.168.1.45",
        "dst_ip": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
        "dst_port": 22,
        "severity": "medium",
        "timestamp": time.time(),
    }
    return alert


def main(sensor_id="sensor-1"):
    secret = SENSOR_SECRETS.get(sensor_id)
    if not secret:
        print(f"[Sensor] Unknown sensor_id '{sensor_id}'.")
        # continue without HMAC if secret unknown (gateway may warn)
    alert = make_alert(sensor_id)
    alert_copy = dict(alert)
    if secret:
        # compute sensor HMAC and attach
        alert_copy["sensor_hmac"] = compute_hmac(secret, json.dumps(alert, sort_keys=True).encode("utf-8"))

    payload = json.dumps(alert_copy).encode("utf-8")
    with socket.create_connection((GATEWAY_HOST, GATEWAY_PORT), timeout=5) as s:
        s.sendall(payload + b"\n")
        # read response
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        print("[Sensor] Gateway response:", resp.decode("utf-8"))


if __name__ == "__main__":
    sid = sys.argv[1] if len(sys.argv) > 1 else "sensor-1"
    main(sid)
