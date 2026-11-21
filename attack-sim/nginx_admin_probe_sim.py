"""Purple team: simulate a web scanner probing admin paths (MITRE T1595.003)."""
import json
import urllib.request

API_URL = "http://127.0.0.1:8000/api/v1/logs"
ATTACKER_IP = "203.0.113.50"
PATHS = ["/admin", "/wp-admin", "/wp-login.php", "/phpmyadmin", "/.env", "/.git/config"]


def send_log(path: str) -> dict:
    payload = {
        "source": "nginx",
        "level": "warning",
        "message": f"GET {path} HTTP/1.1 404",
        "source_ip": ATTACKER_IP,
        "raw": f'{ATTACKER_IP} - - "GET {path} HTTP/1.1" 404 153 "-" "Nmap Scripting Engine"',
    }
    request = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read())


def main():
    print(f"[*] Simulating admin path scan from {ATTACKER_IP}")
    total_alerts = 0
    for path in PATHS:
        result = send_log(path)
        total_alerts += result["alerts_triggered"]
        print(f"  -> {path:<16} alerts_triggered={result['alerts_triggered']}")
    if total_alerts:
        print("[+] DETECTED: rule VIG-0002 fired")
    else:
        print("[-] NOT DETECTED: review rule VIG-0002")


if __name__ == "__main__":
    main()
