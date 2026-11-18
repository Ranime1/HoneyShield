from pathlib import Path
from pymongo import MongoClient

CONFIG_FILE = Path("/home/adminhs/honeyshield-ai/config/mongodb.env")


def load_config():
    config = {}

    with CONFIG_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            key, separator, value = line.partition("=")

            if separator:
                config[key.strip()] = value.strip()

    required = [
        "MONGO_HOST",
        "MONGO_PORT",
        "MONGO_DATABASE",
        "MONGO_USER",
        "MONGO_PASSWORD",
    ]

    for key in required:
        if not config.get(key):
            raise ValueError(f"Configuration manquante : {key}")

    return config


def get_mongodb_connection():
    config = load_config()

    client = MongoClient(
        host=config["MONGO_HOST"],
        port=int(config["MONGO_PORT"]),
        username=config["MONGO_USER"],
        password=config["MONGO_PASSWORD"],
        authSource=config["MONGO_DATABASE"],
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=5000,
    )

    try:
        client.admin.command("ping")
    except Exception:
        client.close()
        raise

    database = client[config["MONGO_DATABASE"]]

    return client, database
