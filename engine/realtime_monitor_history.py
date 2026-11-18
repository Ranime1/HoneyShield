
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
from engine.threat_history_analyzer import analyze_ip

EVE_FILE = Path("/var/log/suricata/eve.json")

LOG_FILE = PROJECT_DIR / "logs/decisions.jsonl"
ALERTS_FILE = PROJECT_DIR / "logs/suricata_pending.jsonl"

RETRY_INTERVAL = 10
HISTORY_HOURS = 168


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
# SAUVEGARDE LOCALE
# ==========================================

def save_local(document, path):

    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with path.open("a", encoding="utf-8") as log:
        log.write(
            json.dumps(
                document,
                ensure_ascii=False
            ) + "\n"
        )

        log.flush()


# ==========================================
# CONNEXION MONGODB
# ==========================================

def connect_mongodb():

    try:
        client, db = get_mongodb_connection()

        print(
            "MongoDB connecte",
            flush=True
        )

        return client, db

    except (PyMongoError, OSError, ValueError) as error:

        print(
            "MongoDB indisponible :",
            error,
            flush=True
        )

        return None, None


# ==========================================
# INSERTION MONGODB AVEC UPSERT
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
                saved.upserted_id,
                flush=True
            )

        else:

            print(
                f"MongoDB : {label} deja enregistre",
                flush=True
            )

        return True

    except PyMongoError as error:

        print(
            f"MongoDB : erreur {label} :",
            error,
            flush=True
        )

        return False


# ==========================================
# SURVEILLANCE EN TEMPS REEL
# ==========================================

def main():

    print(
        "HoneyShield AI - Surveillance avec MongoDB",
        flush=True
    )

    LOG_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    ALERTS_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    client, db = connect_mongodb()

    last_retry = time.monotonic()

    print(
        "En attente des nouvelles alertes Suricata...",
        flush=True
    )

    try:

        with EVE_FILE.open(
            "r",
            encoding="utf-8"
        ) as file:

            # Ignorer les anciens evenements
            file.seek(0, 2)

            while True:

                # ==================================
                # RECONNEXION MONGODB
                # ==================================

                if (
                    client is None
                    and time.monotonic() - last_retry
                    >= RETRY_INTERVAL
                ):

                    last_retry = time.monotonic()

                    client, db = connect_mongodb()

                    if client is not None:

                        print(
                            "Connexion MongoDB retablie",
                            flush=True
                        )

                # ==================================
                # LECTURE SURICATA
                # ==================================


                line = file.readline()

                if not line:

                    # Detecter une troncature de eve.json
                    try:
                        current_size = EVE_FILE.stat().st_size

                        if current_size < file.tell():
                            print(
                                "Rotation Suricata detectee : "
                                "reprise au debut de eve.json",
                                flush=True
                            )
                            file.seek(0)

                    except OSError as error:
                        print(
                            "Erreur verification journal Suricata :",
                            error,
                            flush=True
                        )

                    time.sleep(0.5)
                    continue

                try:

                    event = json.loads(line)

                except json.JSONDecodeError:

                    print(
                        "Ligne JSON Suricata invalide",
                        flush=True
                    )

                    continue

                if not isinstance(event, dict):
                    continue

                if event.get("event_type") != "alert":
                    continue

                # ==================================
                # IDENTIFIANT UNIQUE
                # ==================================

                event_id = hashlib.sha256(
                    line.encode("utf-8")
                ).hexdigest()

                event["event_id"] = event_id

                # ==================================
                # SAUVEGARDE LOCALE DE L'ALERTE
                # ==================================

                save_local(
                    event,
                    ALERTS_FILE
                )

                # ==================================
                # DECISION INITIALE
                # ==================================

                result = analyze(event)

                if result is None:
                    continue

                result["history_score"] = None
                result["history_level"] = "UNAVAILABLE"

                # ==================================
                # ANALYSE HISTORIQUE
                # AVANT INSERTION MONGODB
                # ==================================

                if db is not None:

                    try:

                        history = analyze_ip(
                            db,
                            event.get("src_ip"),
                            hours=HISTORY_HOURS
                        )

                        result["history_score"] = (
                            history["score"]
                        )

                        result["history_level"] = (
                            history["level"]
                        )

                    except PyMongoError as error:

                        print(
                            "Connexion historique perdue :",
                            error,
                            flush=True
                        )

                        if client is not None:
                            client.close()

                        client = None
                        db = None
                        last_retry = (
                            time.monotonic()
                            - RETRY_INTERVAL
                        )

                    except Exception as error:

                        print(
                            "Erreur analyse historique :",
                            error,
                            flush=True
                        )

                # ==================================
                # AFFICHAGE DE LA DECISION
                # ==================================

                print(
                    json.dumps(
                        result,
                        indent=2,
                        ensure_ascii=False
                    ),
                    flush=True
                )

                # ==================================
                # SAUVEGARDE LOCALE DECISION
                # ==================================

                save_local(
                    result,
                    LOG_FILE
                )

                # ==================================
                # INSERTIONS MONGODB
                # ==================================

                if db is not None:

                    alerts_collection = db[
                        "suricata_alerts"
                    ]

                    decisions_collection = db[
                        "security_decisions"
                    ]

                    alert_saved = save_mongodb(
                        alerts_collection,
                        event,
                        "alerte Suricata"
                    )

                    decision_saved = save_mongodb(
                        decisions_collection,
                        result,
                        "decision"
                    )

                    if not (
                        alert_saved and decision_saved
                    ):

                        print(
                            "MongoDB : synchronisation "
                            "locale necessaire",
                            flush=True
                        )

                        if client is not None:
                            client.close()

                        client = None
                        db = None

                        last_retry = (
                            time.monotonic()
                            - RETRY_INTERVAL
                        )

                else:

                    print(
                        "MongoDB indisponible : "
                        "evenement conserve localement",
                        flush=True
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
        print(
            "\nSurveillance arretee",
            flush=True
        )
