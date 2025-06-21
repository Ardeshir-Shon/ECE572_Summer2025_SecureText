#!/usr/bin/env python3


import json
import hashlib
import bcrypt
import time
import os

base_dir = os.path.dirname(os.path.dirname(__file__))  # go up from src/
users_path = os.path.join(base_dir, 'users.json')


with open(users_path, 'r') as f:
    users = json.load(f)


wordlist = ['12345', 'password', 'letmein', 'admin', 'secret', 'welcome']


print("\n=== salted SHA-256 crack ===")
sha_users = {
    u: (data['password'], data.get('salt', ''))
    for u, data in users.items()
    if data.get('hash_alg') == 'sha256'
}

start = time.time()
for username, (stored_hash, salt) in sha_users.items():
    for pw in wordlist:
        candidate = hashlib.sha256((salt + pw).encode()).hexdigest()
        if candidate == stored_hash:
            print(f"[+] Cracked SHA256 for {username}: {pw}")
            break
    else:
        print(f"[-] Failed to crack SHA256 for {username}")
elapsed = time.time() - start
print(f"Time for SHA-256 dictionary attack: {elapsed:.4f} seconds")

print("\n=== bcrypt (salted) dictionary attack ===")
bcrypt_users = {
    u: data['password']
    for u, data in users.items()
    if data.get('password', '').startswith('$2b$') or data.get('password', '').startswith('$2a$')
}

start = time.time()
for username, hashed_pw in bcrypt_users.items():
    cracked = False
    for pw in wordlist:
        try:
            if bcrypt.checkpw(pw.encode(), hashed_pw.encode()):
                print(f"[!] Cracked bcrypt for {username}: {pw}")
                cracked = True
                break
        except ValueError:
            print(f"[!] Skipping invalid bcrypt hash for {username}")
            break
    if not cracked:
        print(f"[✓] Could not crack bcrypt for {username} (secure)")
elapsed = time.time() - start
print(f"Time for bcrypt dictionary attempts: {elapsed:.4f} seconds")