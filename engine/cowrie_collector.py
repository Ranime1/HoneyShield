
import hashlib
import json
import sys
from pathlib import Path

from pymongo.errors import PyMongoError

PROJECT_DIR = Path("/home/adminhs/honeyshield-ai")
sys.path.insert(0, str(PROJECT_DIR))

from engine.mongodb_client import get_mongodb_connection

COWRIE_DIR = PROJECT_DIR / "logs/cowrie"


def get_log_files():
    files = []

    for path in COWRIE_DIR.iterdir():
        if not path.is_file():
            continue

        if path.name == "cowrie.json":
            files.append(path)

        elif (
            path.name.startswith("cowrie.json.")
            and len(path.name) == len("cowrie.json.YYYY-MM-DD")
            and path.name[12:16].isdigit()
            and path.name[16] == "-"
            and path.name[17:19].isdigit()
            and path.name[19] == "-"
            and path.name[20:22].isdigit()
        ):
            files.append(path)

    return sorted(files)


def import_cowrie_events():
    print("HoneyShield AI - Importation Cowrie", flush=True)

    if not COWRIE_DIR.exists():
        print("Dossier Cowrie introuvable", flush=True)
        return

    files = get_log_files()

    if not files:
        print("Aucun journal Cowrie trouve", flush=True)
        return

    client = None
    inserted = 0
    existing = 0
    ignored = 0

    try:
        client, db = get_mongodb_connection()
        collection = db["cowrie_sessions"]

        print("MongoDB connecte", flush=True)

        for path in files:
            print("Lecture :", path.name, flush=True)

            with path.open("r", encoding="utf-8") as file:
                for line in file:
                    if not line.strip():
                        ignored += 1
                        continue

                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        ignored += 1
                        continue

                    if not isinstance(event, dict):
                        ignored += 1
                        continue

                    # Meme methode que l'ancien collecteur
                    event_id = "cowrie-" + hashlib.sha256(
                        line.encode("utf-8")
                    ).hexdigest()

                    event["event_id"] = event_id

                    # Upsert : insertion seulement si absent
                    result = collection.update_one(
                        {"event_id": event_id},
                        {"$setOnInsert": event},
                        upsert=True
                    )

                    if result.upserted_id is not None:
                        inserted += 1
                    else:
                        existing += 1

        print("\nImportation terminee", flush=True)
        print("Fichiers analyses :", len(files), flush=True)
        print("Evenements importes :", inserted, flush=True)
        print("Evenements deja presents :", existing, flush=True)
        print("Lignes ignorees :", ignored, flush=True)

    except (PyMongoError, OSError, ValueError) as error:
        print("Erreur importation Cowrie :", error, flush=True)
        raise

    finally:
        if client is not None:
            client.close()


if __name__ == "__main__":
    import_cowrie_events()
