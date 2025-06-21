#!/usr/bin/env python3
import json
import os
import sys
import bcrypt

# Adjust this to point to your actual users.json file
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(ROOT_DIR, 'users.json')


def _hash_password(password: str, rounds: int = 12) -> str:
    """Return bcrypt hash of the given password."""
    return bcrypt.hashpw(password.encode('utf-8'),
                         bcrypt.gensalt(rounds=rounds)).decode('utf-8')


def migrate():
    if not os.path.exists(USERS_FILE):
        print(f"[-] {USERS_FILE} not found")
        return 1

    try:
        with open(USERS_FILE, 'r') as f:
            users = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"[-] Failed to load users: {e}")
        return 1

    migrated = 0
    legacy_fields_removed = 0

    for username, data in users.items():
        pw = data.get('password', '')
        alg = data.get('hash_alg')

        # Case 1: Legacy password (plaintext or sha256)
        if not pw.startswith('$2'):
            users[username]['password'] = _hash_password(pw)
            migrated += 1

        # Remove legacy fields if present
        if 'salt' in data:
            users[username].pop('salt', None)
            legacy_fields_removed += 1
        if 'hash_alg' in data:
            users[username].pop('hash_alg', None)
            legacy_fields_removed += 1

    if migrated or legacy_fields_removed:
        try:
            with open(USERS_FILE, 'w') as f:
                json.dump(users, f, indent=2)
            print(f"[✓] Migrated {migrated} account(s), cleaned {legacy_fields_removed} legacy field(s)")
        except IOError as e:
            print(f"[-] Failed to save updated users: {e}")
            return 1
    else:
        print("[*] No migration needed")

    return 0


if __name__ == '__main__':
    sys.exit(migrate())
