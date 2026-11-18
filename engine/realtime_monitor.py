import json
import time
from pathlib import Path

EVE_FILE = Path("/var/log/suricata/eve.json")
LOG_FILE = Path("/home/adminhs/honeyshield-ai/logs/decisions.jsonl")

def analyze(event):
    if event.get("event_type") != "alert":
        return

    alert = event.get("alert", {})
    signature = alert.get("signature", "")
    severity = alert.get("severity", 3)

    if "INFO" in signature.upper() or "HoneyShield - Test HTTP" in signature:
        decision = "MONITOR"
    elif severity in (1, 2):
        decision = "INVESTIGATE"
    else:
        decision = "MONITOR"

    result = {
        "timestamp": event.get("timestamp"),
        "source_ip": event.get("src_ip"),
        "destination_ip": event.get("dest_ip"),
        "signature": signature,
        "severity": severity,
        "decision": decision
    }

    print(json.dumps(result, indent=2), flush=True)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    with LOG_FILE.open("a", encoding="utf-8") as log:
        log.write(json.dumps(result, ensure_ascii=False) + "\n")


def main():
    print("HoneyShield AI - Surveillance en temps réel")
    print("En attente des nouvelles alertes Suricata...")

    with EVE_FILE.open("r") as file:
        file.seek(0, 2)

        while True:
            line = file.readline()

            if not line:
                time.sleep(0.5)
                continue

            try:
                event = json.loads(line)
                analyze(event)

            except json.JSONDecodeError:
                continue


if __name__ == "__main__":
    main()
