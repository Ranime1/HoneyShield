import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_DIR = Path("/home/adminhs/honeyshield-ai")
sys.path.insert(0, str(PROJECT_DIR))

from engine.mongodb_client import get_mongodb_connection


def parse_timestamp(value):
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if isinstance(value, str):
        try:
            return datetime.fromisoformat(
                value.replace("Z", "+00:00")
            ).astimezone(timezone.utc)
        except ValueError:
            return None

    return None


def in_window(event, start, end):
    timestamp = parse_timestamp(event.get("timestamp"))
    return timestamp is not None and start <= timestamp <= end

def has_alert_burst(alerts, minutes=10, threshold=3):
    timestamps = sorted(
        timestamp
        for event in alerts
        if (timestamp := parse_timestamp(event.get("timestamp"))) is not None
    )

    left = 0
    window = timedelta(minutes=minutes)

    for right in range(len(timestamps)):
        while timestamps[right] - timestamps[left] > window:
            left += 1

        if right - left + 1 >= threshold:
            return True

    return False

def analyze_ip(db, ip, hours=24):
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)

    # Les horodatages historiques peuvent etre
    # stockes comme texte ISO ou comme date BSON.
    # Filtrage en Python pour ce premier prototype.

    alerts = [
        event
        for event in db["suricata_alerts"].find({"src_ip": ip})
        if in_window(event, start, end)
    ]

    decisions = [
        event
        for event in db["security_decisions"].find(
            {"source_ip": ip}
        )
        if in_window(event, start, end)
    ]

    cowrie = [
        event
        for event in db["cowrie_sessions"].find({"src_ip": ip})
        if in_window(event, start, end)
    ]

    sessions = {
        event["session"]
        for event in cowrie
        if event.get("session")
    }

    login_failures = sum(
        event.get("eventid") == "cowrie.login.failed"
        for event in cowrie
    )

    login_successes = sum(
        event.get("eventid") == "cowrie.login.success"
        for event in cowrie
    )

    commands = sum(
        event.get("eventid") == "cowrie.command.input"
        for event in cowrie
    )

    critical_alerts = sum(
        event.get("alert", {}).get("severity") == 1
        for event in alerts
    )

    # Score pedagogique, a calibrer.
    score = 0
    reasons = []

    if has_alert_burst(alerts, minutes=10, threshold=3):
        score += 20
        reasons.append("Au moins 3 alertes Suricata : +20")

    if critical_alerts >= 1:
        score += 25
        reasons.append("Alerte de severite 1 : +25")

    if login_failures >= 3:
        score += 20
        reasons.append("3 echecs SSH ou plus : +20")

    if commands >= 1:
        score += 20
        reasons.append("Commandes observees dans Cowrie : +20")

    if len(sessions) >= 2:
        score += 15
        reasons.append("Plusieurs sessions Cowrie : +15")

    score = min(score, 100)

    if score >= 70:
        level = "ELEVE"
    elif score >= 30:
        level = "MOYEN"
    else:
        level = "FAIBLE"

    return {
        "ip": ip,
        "hours": hours,
        "alerts": len(alerts),
        "critical_alerts": critical_alerts,
        "decisions": len(decisions),
        "cowrie_events": len(cowrie),
        "cowrie_sessions": len(sessions),
        "login_failures": login_failures,
        "login_successes": login_successes,
        "commands": commands,
        "score": score,
        "level": level,
        "reasons": reasons,
    }


def main():
    parser = argparse.ArgumentParser(
        description="HoneyShield Threat History Analyzer"
    )
    parser.add_argument("--ip", required=True)
    parser.add_argument("--hours", type=int, default=24)
    args = parser.parse_args()

    if args.hours <= 0:
        parser.error("--hours doit etre positif")

    client = None

    try:
        client, db = get_mongodb_connection()
        report = analyze_ip(db, args.ip, args.hours)

        print("\n=== HONEYSHIELD THREAT HISTORY ===")
        print("IP analysee :", report["ip"])
        print("Periode :", report["hours"], "heures")
        print("Alertes Suricata :", report["alerts"])
        print("Alertes critiques :", report["critical_alerts"])
        print("Decisions historiques :", report["decisions"])
        print("Evenements Cowrie :", report["cowrie_events"])
        print("Sessions Cowrie :", report["cowrie_sessions"])
        print("Echecs SSH :", report["login_failures"])
        print("Logins acceptes :", report["login_successes"])
        print("Commandes Cowrie :", report["commands"])
        print("Score :", report["score"], "/ 100")
        print("Niveau :", report["level"])

        print("\nJustification du score :")
        for reason in report["reasons"]:
            print("-", reason)

        if not report["reasons"]:
            print("- Aucun critere de score declenche")

    finally:
        if client is not None:
            client.close()


if __name__ == "__main__":
    main()
