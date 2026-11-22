#!/usr/bin/env python3
"""HoneyShield AI: décisions MongoDB -> sets nftables; journal de changements.

Conçu pour la topologie de laboratoire HoneyShield actuelle. Ne déploie pas de
règles Suricata et ne remplace pas les règles nftables existantes.
"""
import argparse
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from bson import ObjectId

PROJECT = Path('/home/adminhs/honeyshield-ai')
sys.path.insert(0, str(PROJECT))
from engine.mongodb_client import get_mongodb_connection

STATE = PROJECT / 'config/nftables_manager_state.json'
PENDING = PROJECT / 'config/nftables_manager_pending.json'
PROCESSED_DB = PROJECT / 'config/nftables_manager_processed.sqlite3'
ALLOWED_IPS = {'10.10.10.10'}  # Laboratoire uniquement. Élargir après validation.
POLL_SECONDS = 5
MAX_EVENT_AGE_SECONDS = 600


def now():
    return datetime.now(timezone.utc)


def evaluate_action(decision, score):
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return 'NO_CHANGE'
    if not 0 <= score <= 100:
        return 'NO_CHANGE'
    if decision == 'INVESTIGATE' and score >= 80:
        return 'BLOCK'
    if decision in ('MONITOR', 'INVESTIGATE') and score >= 60:
        return 'REDIRECT'
    return 'NO_CHANGE'


def validate_ip(value):
    try:
        ip = ipaddress.ip_address(value)
    except (ValueError, TypeError) as exc:
        raise ValueError('IP invalide') from exc
    if ip.version != 4 or str(ip) not in ALLOWED_IPS:
        raise ValueError('IP non autorisée pour le laboratoire')
    return str(ip)


def command(*args, stdin=None):
    return subprocess.run(
        ['nft', *args], input=stdin, text=True, capture_output=True,
        check=True, timeout=10,
    ).stdout


def in_set(family, table, name, ip):
    output = command('list', 'set', family, table, name)
    return re.search(r'(?<![\d.])' + re.escape(ip) + r'(?![\d.])', output) is not None


def current_state(ip):
    blocked = in_set('inet', 'honeyshield', 'blocked_sources', ip)
    redirected = in_set('ip', 'honey_nat', 'redirected_sources', ip)
    if blocked and redirected:
        return 'BOTH'  # État incohérent, réconcilié par l'action suivante.
    if blocked:
        return 'BLOCK'
    if redirected:
        return 'REDIRECT'
    return 'NONE'


def apply_nftables_action(action, source_ip):
    """Retourne True uniquement si les sets ont réellement changé."""
    ip = validate_ip(source_ip)
    if action not in ('BLOCK', 'REDIRECT', 'UNBLOCK'):
        raise ValueError('Action non reconnue')
    blocked = in_set('inet', 'honeyshield', 'blocked_sources', ip)
    redirected = in_set('ip', 'honey_nat', 'redirected_sources', ip)
    commands = []

    if action == 'BLOCK':
        if redirected:
            commands.append(f'delete element ip honey_nat redirected_sources {{ {ip} }}')
        if not blocked:
            commands.append(f'add element inet honeyshield blocked_sources {{ {ip} }}')
    elif action == 'REDIRECT':
        # Un BLOCK ne peut pas être affaibli par une décision ultérieure.
        if blocked:
            return False
        if not redirected:
            commands.append(f'add element ip honey_nat redirected_sources {{ {ip} }}')
    else:  # UNBLOCK : retrait explicite des deux sets.
        if blocked:
            commands.append(f'delete element inet honeyshield blocked_sources {{ {ip} }}')
        if redirected:
            commands.append(f'delete element ip honey_nat redirected_sources {{ {ip} }}')

    if not commands:
        return False
    # Un seul lot nft = opérations atomiques au niveau de ce lot.
    command('-f', '-', stdin='\n'.join(commands) + '\n')
    expected = {'BLOCK': 'BLOCK', 'REDIRECT': 'REDIRECT', 'UNBLOCK': 'NONE'}[action]
    actual = current_state(ip)
    if actual != expected:
        raise RuntimeError(f'État nftables incorrect : {actual} != {expected}')
    return True


def atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(tmp, flags, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def checkpoint():
    if not STATE.exists():
        raise RuntimeError('Checkpoint absent : initialiser le fichier state AVANT --apply')
    with STATE.open(encoding='utf-8') as f:
        saved = json.load(f)
    return ObjectId(saved['last_processed_id'])


def save_checkpoint(oid):
    atomic_json(STATE, {'last_processed_id': str(oid)})


def event_fresh(document):
    ts = document.get('timestamp')
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        except ValueError:
            return False
    if not isinstance(ts, datetime):
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    age = (now() - ts.astimezone(timezone.utc)).total_seconds()
    return -60 <= age <= MAX_EVENT_AGE_SECONDS


def record_change(db, pending):
    """Un seul document par changement, même après une reprise."""
    document = {
        'change_id': pending['change_id'],
        'event_id': pending.get('event_id'),
        'source_ip': pending['ip'],
        'monitor_decision': pending.get('monitor_decision'),
        'history_score': pending.get('history_score'),
        'action': pending['action'],
        'previous_state': pending['previous_state'],
        'new_state': {'BLOCK': 'BLOCK', 'REDIRECT': 'REDIRECT', 'UNBLOCK': 'NONE'}[pending['action']],
        'reason': pending['reason'],
        'status': 'applied',
        'timestamp': now(),
    }
    db['firewall_changes'].update_one(
        {'change_id': pending['change_id']},
        {'$setOnInsert': document},
        upsert=True,
    )


def complete_pending(db):
    """Reprise d'un changement interrompu, avant toute nouvelle décision."""
    if not PENDING.exists():
        return
    with PENDING.open(encoding='utf-8') as f:
        pending = json.load(f)
    ip, action = pending['ip'], pending['action']
    before = current_state(validate_ip(ip))
    apply_nftables_action(action, ip)
    after = current_state(ip)
    expected = {'BLOCK': 'BLOCK', 'REDIRECT': 'REDIRECT', 'UNBLOCK': 'NONE'}[action]
    if after != expected:
        raise RuntimeError(f'Reprise impossible : {after} != {expected}')
    # Un journal préparé avant l'action couvre un crash après nft mais avant Mongo.
    # Dans ce laboratoire, un seul gestionnaire est autorisé à changer ces sets.
    record_change(db, pending)
    # L'historique de traitement est désormais géré par SQLite, pas par l'ordre des ObjectId.
    PENDING.unlink()
    print(f'CHANGEMENT {action} enregistré pour {ip} (avant={before})', flush=True)


def commit_change(db, action, ip, *, document=None, reason='decision'):
    ip = validate_ip(ip)
    before = current_state(ip)
    if action == 'BLOCK' and before == 'BLOCK':
        return False
    if action == 'REDIRECT' and before in ('REDIRECT', 'BLOCK'):
        return False
    if action == 'UNBLOCK' and before == 'NONE':
        return False
    if PENDING.exists():
        raise RuntimeError('Changement précédent non finalisé : reprise nécessaire')
    pending = {
        'change_id': str(uuid.uuid4()),
        'document_id': str(document['_id']) if document else None,
        'event_id': document.get('event_id') if document else None,
        'monitor_decision': document.get('decision') if document else None,
        'history_score': document.get('history_score') if document else None,
        'ip': ip,
        'action': action,
        'previous_state': before,
        'reason': reason,
    }
    # Écriture locale AVANT nft : protection contre le crash nft -> Mongo.
    atomic_json(PENDING, pending)
    complete_pending(db)
    return True


def restore_from_mongodb(db, dry_run=False):
    """Restaure les derniers états enregistrés (ex. après nftables.service restart)."""
    desired = {}
    records = list(db['firewall_changes'].find(
        {'status': 'applied', 'source_ip': {'$in': sorted(ALLOWED_IPS)}}
    ).sort([('timestamp', 1), ('_id', 1)]))
    for record in records:
        state = record.get('new_state')
        if state in ('BLOCK', 'REDIRECT', 'NONE'):
            desired[record['source_ip']] = state
    for ip, target in desired.items():
        actual = current_state(ip)
        if target == 'BLOCK' and actual != 'BLOCK':
            print(f'RESTORE {ip}: {actual} -> BLOCK', flush=True)
            if not dry_run:
                commit_change(db, 'BLOCK', ip, reason='restore')
        elif target == 'REDIRECT' and actual == 'NONE':
            print(f'RESTORE {ip}: NONE -> REDIRECT', flush=True)
            if not dry_run:
                commit_change(db, 'REDIRECT', ip, reason='restore')
        elif target == 'NONE' and actual != 'NONE':
            print(f'RESTORE {ip}: {actual} -> NONE', flush=True)
            if not dry_run:
                commit_change(db, 'UNBLOCK', ip, reason='restore')
        elif target == 'REDIRECT' and actual == 'BLOCK':
            # On ne dégrade jamais BLOCK implicitement.
            print(f'ATTENTION {ip}: BLOCK conservé, REDIRECT ignoré', flush=True)


def event_time(document):
    """Horodatage pour ordonner des événements hétérogènes (BSON ou ISO)."""
    ts = document.get('timestamp')
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        except ValueError:
            ts = None
    if not isinstance(ts, datetime):
        return datetime.min.replace(tzinfo=timezone.utc)
    return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts.astimezone(timezone.utc)


def open_processed_db(db):
    """Journal local des décisions examinées, indépendant de l'ordre des ObjectId.

    Première utilisation : marquer atomiquement toutes les décisions déjà présentes
    comme historiques, pour ne pas appliquer les anciens tests au déploiement.
    """
    PROCESSED_DB.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(PROCESSED_DB), timeout=10)
    connection.execute('PRAGMA journal_mode=WAL')
    connection.execute('PRAGMA busy_timeout=10000')
    connection.execute('CREATE TABLE IF NOT EXISTS processed (id TEXT PRIMARY KEY)')
    connection.execute('CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT)')
    initialized = connection.execute(
        "SELECT value FROM metadata WHERE name='initialized'"
    ).fetchone()
    if not initialized:
        old_ids = [str(item['_id']) for item in db['security_decisions'].find({}, {'_id': 1})]
        with connection:
            connection.executemany(
                'INSERT OR IGNORE INTO processed(id) VALUES (?)',
                ((oid,) for oid in old_ids)
            )
            connection.execute(
                "INSERT INTO metadata(name,value) VALUES ('initialized','yes')"
            )
        print(f'Initialisation : {len(old_ids)} décisions historiques ignorées', flush=True)
    return connection


def process_new(db, dry_run):
    """Ne traiter que les ObjectId non encore vus, peu importe leur ordre."""
    processed = open_processed_db(db)
    try:
        documents = list(db['security_decisions'].find({}))
        documents.sort(key=lambda d: (event_time(d), str(d['_id'])))
        count = 0
        for doc in documents:
            oid = str(doc['_id'])
            if processed.execute('SELECT 1 FROM processed WHERE id=?', (oid,)).fetchone():
                continue
            ip = doc.get('source_ip')
            decision = doc.get('decision')
            score = doc.get('history_score')
            action = evaluate_action(decision, score)
            if not event_fresh(doc):
                action = 'NO_CHANGE'
            print(f'_id={oid} ip={ip} decision={decision} score={score} => {action}', flush=True)
            if dry_run:
                count += 1
                continue
            if action != 'NO_CHANGE':
                try:
                    commit_change(db, action, ip, document=doc)
                except ValueError as exc:
                    print(f'IGNORÉ : {exc}', flush=True)
            # La validation ou l'historisation nftables s'est terminée avant ce commit.
            with processed:
                processed.execute('INSERT OR IGNORE INTO processed(id) VALUES (?)', (oid,))
            count += 1
        if count == 0:
            print('Aucune nouvelle décision', flush=True)
        return count
    finally:
        processed.close()


def self_test():
    samples = [
        ('MONITOR', 35, 'NO_CHANGE'),
        ('MONITOR', 70, 'REDIRECT'),
        ('INVESTIGATE', 65, 'REDIRECT'),
        ('INVESTIGATE', 90, 'BLOCK'),
        ('INVESTIGATE', 40, 'NO_CHANGE'),
        ('MONITOR', None, 'NO_CHANGE'),
    ]
    for decision, score, expected in samples:
        result = evaluate_action(decision, score)
        assert result == expected, (decision, score, result, expected)
        print(f'OK {decision} {score} -> {result}')
    print('6/6 tests de décision réussis')


def main():
    parser = argparse.ArgumentParser(description='HoneyShield AI — nftables Manager')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--watch', action='store_true', help='Surveillance continue')
    mode.add_argument('--unblock', metavar='IP', help='Déblocage manuel et historisé')
    mode.add_argument('--restore', action='store_true', help='Restaurer depuis MongoDB')
    mode.add_argument('--self-test', action='store_true', help='Tests sans MongoDB ni nftables')
    parser.add_argument('--apply', action='store_true', help='Autoriser les changements réels')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.watch and not args.apply:
        raise SystemExit('--watch nécessite --apply (sinon utiliser le mode simulation)')
    if args.unblock and not args.apply:
        raise SystemExit('--unblock nécessite --apply')
    if args.restore and not args.apply:
        raise SystemExit('--restore nécessite --apply')
    print('HoneyShield nftables Manager — ' + ('APPLICATION' if args.apply else 'SIMULATION'), flush=True)
    while True:
        client = None
        try:
            # Aucune action si la connexion MongoDB est indisponible.
            client, db = get_mongodb_connection()
            client.admin.command('ping')
            if args.apply:
                complete_pending(db)
                restore_from_mongodb(db)
            if args.unblock:
                if current_state(validate_ip(args.unblock)) != 'NONE':
                    commit_change(db, 'UNBLOCK', args.unblock, reason='manual_unblock')
                else:
                    print('Aucune règle à retirer')
                return
            if args.restore:
                return
            process_new(db, dry_run=not args.apply)
        except Exception as exc:
            print(f'ERREUR : {type(exc).__name__}: {exc}', file=sys.stderr, flush=True)
            if not args.watch:
                raise SystemExit(1)
        finally:
            if client is not None:
                client.close()
        if not args.watch:
            return
        time.sleep(POLL_SECONDS)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Arrêt demandé', flush=True)
