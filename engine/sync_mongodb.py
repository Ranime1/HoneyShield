import json
import sys
from pathlib import Path
from pymongo.errors import PyMongoError

PROJECT_DIR = Path("/home/adminhs/honeyshield-ai")
sys.path.insert(0, str(PROJECT_DIR))

from engine.mongodb_client import get_mongodb_connection

DECISIONS_FILE = PROJECT_DIR / "logs/decisions.jsonl"
ALERTS_FILE = PROJECT_DIR / "logs/suricata_pending.jsonl"

def sync_collection(collection, path, label):

    inserted = 0
    existing = 0
    skipped = 0

    if not path.exists():
        print(f"{label} : fichier local absent")
        return

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            try:
                document = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            if not isinstance(document, dict):
                skipped += 1
                continue
            event_id = document.get("event_id")
            if not isinstance(event_id, str) or not event_id:
                skipped += 1
                continue
            result = collection.update_one(
                {"event_id": event_id},
                {"$setOnInsert": document},
                upsert=True
            )
            if result.upserted_id is not None:
                inserted += 1
            else:
                existing += 1
    print(f"\n{label}")
    print("Documents recuperes :", inserted)
    print("Documents deja presents :", existing)
    print("Lignes ignorees :", skipped)

def synchronize():
    print("HoneyShield AI - Synchronisation MongoDB")
    client = None
    try:
        client, db = get_mongodb_connection()
        print("Connexion MongoDB reussie")
        sync_collection(
            db["suricata_alerts"],
            ALERTS_FILE,
            "Alertes Suricata"
        )
        sync_collection(
            db["security_decisions"],
            DECISIONS_FILE,
            "Decisions de securite"
        )
        print("\nSynchronisation terminee")
    except (PyMongoError, OSError, ValueError) as error:
        print("Synchronisation interrompue :", error)
        print("Journaux locaux conserves")
        raise
    finally:
        if client is not None:
            client.close()

if __name__ == "__main__":
    synchronize()
