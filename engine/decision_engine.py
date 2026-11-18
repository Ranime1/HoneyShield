import json
from pathlib import Path

EVE_FILE = Path("/var/log/suricata/eve.json")


def decide(event):
    if event.get("event_type") != "alert":
        return None

    alert = event.get("alert", {})
    signature = alert.get("signature", "")
    severity = alert.get("severity", 3)

    if severity == 1:
        decision = "BLOCK"
    elif severity == 2:
        decision = "REDIRECT"
    else:
        decision = "ALLOW"

    return {
        "source_ip": event.get("src_ip"),
        "destination_ip": event.get("dest_ip"),
        "signature": signature,
        "severity": severity,
        "decision": decision,
    }


def main():
    if not EVE_FILE.exists():
        print("Fichier eve.json introuvable")
        return

    with EVE_FILE.open("r") as file:
        for line in file:
            try:
                event = json.loads(line)
                result = decide(event)

                if result:
                    print(json.dumps(result, indent=2))

            except json.JSONDecodeError:
                continue


if __name__ == "__main__":
    main()

