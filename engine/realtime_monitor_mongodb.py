
import json
import sys
import time
import hashlib
from pathlib import Path

from pymongo.errors import PyMongoError

# ==========================================
# CONFIGURATION HONEYSHIELD AI
# ==========================================

PROJECT_DIR = Path("/home/adminhs/honeyshield-ai")
sys.path.insert(0, str(PROJECT_DIR))

from engine.mongodb_client import get_mongodb_connection

EVE_FILE = Path("/var/log/suricata/eve.json")
LOG_FILE = PROJECT_DIR / "logs/decisions.jsonl"


# ==========================================
# ANALYSE ET DECISION
# ==========================================

def analyze(event):

    if event.get("event_type") != "alert":
        return None

    alert = event.get("alert", {})

    signature = alert.get("signature", "")
    severity = alert.get("severity", 3)

    if (
        "INFO" in signature.upper()
        or "HoneyShield - Test HTTP" in signature
    ):
        decision = "MONITOR"

    elif severity in (1, 2):
        decision = "INVESTIGATE"

    else:
        decision = "MONITOR"

    return {
        "event_id": event.get("event_id"),
        "timestamp": event.get("timestamp"),
        "source_ip": event.get("src_ip"),
        "destination_ip": event.get("dest_ip"),
        "signature": signature,
        "severity": severity,
        "decision": decision
    }


# ==========================================
# ENREGISTREMENT LOCAL
# ==========================================

def save_local(result):

    LOG_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with LOG_FILE.open("a", encoding="utf-8") as log:

        log.write(
            json.dumps(result, ensure_ascii=False) + "\n"
        )


# ==========================================
# ENREGISTREMENT MONGODB
# ==========================================

def save_mongodb(collection, document, label):

    try:

        saved = collection.update_one(
            {"event_id": document["event_id"]},
            {"$setOnInsert": document.copy()},
            upsert=True
        )

        if saved.upserted_id is not None:

            print(
                f"MongoDB : nouveau document {label} insere",
                saved.upserted_id
            )

        else:

            print(
                f"MongoDB : {label} deja enregistre"
            )

        return True

    except PyMongoError as error:

        print(
            f"MongoDB : erreur enregistrement {label} :",
            error
        )

        return False


# ==========================================
# SURVEILLANCE EN TEMPS REEL
# ==========================================

def main():

    print("HoneyShield AI - Surveillance avec MongoDB")

    client = None
    decisions_collection = None
    alerts_collection = None

    # Connexion MongoDB

    try:

        client, db = get_mongodb_connection()

        decisions_collection = db["security_decisions"]
        alerts_collection = db["suricata_alerts"]

        print("MongoDB connecte")

    except (PyMongoError, OSError, ValueError) as error:

        print("MongoDB indisponible :", error)

    LOG_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    print("En attente des nouvelles alertes Suricata...")

    try:

        with EVE_FILE.open("r", encoding="utf-8") as file:

            # Ignorer les evenements anciens
            file.seek(0, 2)

            while True:

                line = file.readline()

                if not line:

                    time.sleep(0.5)
                    continue

                # Lire evenement JSON

                try:

                    event = json.loads(line)

                except json.JSONDecodeError:

                    continue

                if event.get("event_type") != "alert":
                    continue

                # Identifiant unique de l'evenement

                event_id = hashlib.sha256(
                    line.encode("utf-8")
                ).hexdigest()

                event["event_id"] = event_id

                # ==================================
                # ENREGISTRER ALERTE SURICATA
                # ==================================

                if alerts_collection is not None:

                    save_mongodb(
                        alerts_collection,
                        event,
                        "alerte Suricata"
                    )

                # ==================================
                # ANALYSER EVENEMENT
                # ==================================

                result = analyze(event)

                if result is None:
                    continue

                print(
                    json.dumps(result, indent=2),
                    flush=True
                )

                # ==================================
                # SAUVEGARDE LOCALE
                # ==================================

                save_local(result)

                # ==================================
                # ENREGISTRER DECISION MONGODB
                # ==================================

                if decisions_collection is not None:

                    save_mongodb(
                        decisions_collection,
                        result,
                        "decision"
                    )

    finally:

        if client is not None:
            client.close()


# ==========================================
# EXECUTION
# ==========================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print("\nSurveillance arretee")
