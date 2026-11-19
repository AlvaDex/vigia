"""Simulates an SSH brute force (MITRE T1110.001) by replaying fake auth.log
events to the Vigía API. No real attack traffic is generated."""
import json
import sys
import urllib.request

API_URL = "http://127.0.0.1:8000/api/v1/logs"
ATTACKER_IP = "203.0.113.5"  # TEST-NET-3: reserved for documentation
USERS = ["root", "admin", "ubuntu", "test", "oracle", "postgres"]


def send(payload: dict) -> dict:
    request = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read())


def main():
    attempts = int(sys.argv[1]) if len(sys.argv) > 1 else 6
    for i in range(attempts):
        user = USERS[i % len(USERS)]
        message = f"Failed password for {user} from {ATTACKER_IP} port {50000 + i} ssh2"
        result = send({
            "source": "ssh",
            "level": "warning",
            "message": message,
            "source_ip": ATTACKER_IP,
        })
        print(f"[{i + 1}/{attempts}] {message} -> alerts_triggered={result['alerts_triggered']}")
    print("\nCheck alerts at http://127.0.0.1:8000/api/v1/alerts")


if __name__ == "__main__":
    main()
