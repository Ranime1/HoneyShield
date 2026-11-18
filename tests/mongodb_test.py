from getpass import getpass
from datetime import datetime, timezone
from pymongo import MongoClient

HOST = "10.10.20.20"
PORT = 27017

username = "honeyshield_app"
password = getpass("Mot de passe MongoDB honeyshield_app : ")

client = MongoClient(
    host=HOST,
    port=PORT,
    username=username,
    password=password,
    authSource="honeyshield_db",
    serverSelectionTimeoutMS=5000,
    connectTimeoutMS=5000
)

try:
    client.admin.command("ping")
    print("Connexion MongoDB réussie !")

    db = client["honeyshield_db"]
    collection = db["security_decisions"]

    document = {
        "timestamp": datetime.now(timezone.utc),
        "source_ip": "10.10.10.10",
        "destination_ip": "10.10.20.20",
        "signature": "HoneyShield - Test MongoDB",
        "severity": 3,
        "decision": "MONITOR",
        "test": True
    }

    result = collection.insert_one(document)
    print("Document inséré :", result.inserted_id)

    saved = collection.find_one({"_id": result.inserted_id})
    print("Document retrouvé :", saved)

except Exception as error:
    print("Erreur MongoDB :", error)

finally:
    client.close()
