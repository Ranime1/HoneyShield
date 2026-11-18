
#!/bin/bash
set -euo pipefail

PROJECT="/home/adminhs/honeyshield-ai"
KEY="/home/adminhs/.ssh/id_ed25519_cowrie"

REMOTE="adminhs@10.10.20.30"
REMOTE_DIR="/home/cowrie/my-honeypot/var/log/cowrie"

DEST_DIR="$PROJECT/logs/cowrie"

mkdir -p "$DEST_DIR"

# Dossier temporaire pour les transferts
STAGE=$(mktemp -d "$DEST_DIR/.transfer.XXXXXX")

trap 'rm -rf -- "$STAGE"' EXIT

echo "HoneyShield AI - Collecte Cowrie"

# Recuperer le journal courant et ses archives
scp -q \
    -i "$KEY" \
    -o BatchMode=yes \
    -o ConnectTimeout=5 \
    "$REMOTE:$REMOTE_DIR/cowrie.json*" \
    "$STAGE/"

echo "Transfert SSH termine"

# Conserver les copies locales
for file in "$STAGE"/cowrie.json*; do
    [ -f "$file" ] || continue

    name=$(basename "$file")
    mv -f -- "$file" "$DEST_DIR/$name"
done

echo "Journaux Cowrie recuperes :"

find "$DEST_DIR" \
    -maxdepth 1 \
    -type f \
    -name 'cowrie.json*' \
    -printf '%f\n' | sort

# Importer tous les fichiers dans MongoDB
"$PROJECT/.venv/bin/python" \
    "$PROJECT/engine/cowrie_collector.py"

echo "Collecte Cowrie terminee"
