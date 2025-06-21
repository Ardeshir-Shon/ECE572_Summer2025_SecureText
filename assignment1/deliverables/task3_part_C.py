#!/usr/bin/env python3
"""
Author: Ardeshir S.
Course: ECE 572; Summer 2025
SecureText Console Messenger
—with bcrypt password hashing, plaintext migration, and a **flawed MD5(k||m) MAC**
(Task-3C demo version – MAC check is bypassed on server side)
"""

import socket
import threading
import json
import os
import sys
import bcrypt
import hashlib
import base64
import re
from datetime import datetime

SHARED_KEY = b'my_shared_secret_key'


# ---------------------------------------------------------------------------
#                             SERVER SIDE
# ---------------------------------------------------------------------------
class SecureTextServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.users_file = 'users.json'
        self.users = self.load_users()
        self.migrate_plaintext_passwords()
        self.active_connections = {}

    def load_users(self):
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                print(f"Warning: Could not load {self.users_file}, starting empty")
        return {}

    def save_users(self):
        try:
            with open(self.users_file, 'w') as f:
                json.dump(self.users, f, indent=2)
        except IOError as e:
            print(f"Error saving users: {e}")

    def migrate_plaintext_passwords(self):
        migrated = False
        for uname, data in list(self.users.items()):
            pw = data.get('password', '')
            if not pw.startswith('$2'):
                data['password'] = self._hash_password(pw)
                data.pop('hash_alg', None)
                migrated = True
            else:
                if 'hash_alg' in data:
                    data.pop('hash_alg')
                    migrated = True
        if migrated:
            print("Migrated legacy passwords → bcrypt")
            self.save_users()

    @staticmethod
    def _hash_password(pw: str, rounds: int = 12) -> str:
        return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds)).decode()

    @staticmethod
    def _verify_password(pw: str, hsh: str) -> bool:
        return bcrypt.checkpw(pw.encode(), hsh.encode())

    @staticmethod
    def _compute_mac_bytes(msg_bytes: bytes) -> str:
        return hashlib.md5(SHARED_KEY + msg_bytes).hexdigest()

    def create_account(self, username, password):
        if username in self.users:
            return False, "Username exists"
        self.users[username] = {
            'password': self._hash_password(password),
            'created_at': datetime.now().isoformat(),
            'reset_question': 'What is your favorite color?',
            'reset_answer': 'blue',
        }
        self.save_users()
        return True, "Account created"

    def authenticate(self, username, password):
        user = self.users.get(username)
        if not user:
            return False, "Not found"
        return (self._verify_password(password, user['password']), "OK" if self._verify_password(password, user['password']) else "Invalid password")

    def reset_password(self, username, new_password):
        if username not in self.users:
            return False, "Not found"
        self.users[username]['password'] = self._hash_password(new_password)
        self.save_users()
        return True, "Reset OK"

    def handle_client(self, conn, addr):
        print(f"[SERVER] Connection from {addr}")
        current_user = None

        try:
            while True:
                raw = conn.recv(4096)
                if not raw:
                    break

                try:
                    msg = json.loads(raw.decode())
                except json.JSONDecodeError:
                    conn.send(b'{"status":"error","message":"Bad JSON"}')
                    continue

                cmd = msg.get('command')

                if cmd == 'CREATE_ACCOUNT':
                    ok, m = self.create_account(msg['username'], msg['password'])
                    resp = {'status': 'success' if ok else 'error', 'message': m}

                elif cmd == 'LOGIN':
                    ok, m = self.authenticate(msg['username'], msg['password'])
                    if ok:
                        current_user = msg['username']
                        self.active_connections[current_user] = conn
                    resp = {'status': 'success' if ok else 'error', 'message': m}

                elif cmd == 'SEND_MESSAGE':
                    if not current_user:
                        resp = {'status': 'error', 'message': 'Not logged in'}
                    else:
                        to = msg['recipient']
                        content = msg['content']
                        if to in self.active_connections:
                            payload = {
                                'type': 'MESSAGE',
                                'from': current_user,
                                'content': content,
                                'timestamp': datetime.now().isoformat()
                            }
                            self.active_connections[to].send(json.dumps(payload).encode())
                            resp = {'status': 'success', 'message': 'Sent'}
                        else:
                            resp = {'status': 'error', 'message': 'Offline'}

                elif cmd == 'EXEC_COMMAND':
                    if not current_user:
                        resp = {'status': 'error', 'message': 'Not logged in'}
                    else:
                        try:
                            payload_bytes = base64.b64decode(msg.get('payload_b64', ''), validate=True)
                        except (base64.binascii.Error, ValueError):
                            resp = {'status': 'error', 'message': 'Bad payload encoding'}
                            conn.send(json.dumps(resp).encode())
                            continue

                        client_mac = msg.get('mac', '').lower()
                        server_mac = self._compute_mac_bytes(payload_bytes)

                        print("\n[DEBUG] payload hex :", payload_bytes.hex())
                        print("[DEBUG] recv  MAC   :", client_mac)
                        print("[DEBUG] calc  MAC   :", server_mac)
                        print("[DEBUG] → Skipping MAC check (bypassed for Task 3C demo)")

                        # Bypass MAC check
                        text = payload_bytes.decode('latin1', errors='ignore')
                        kv = dict(re.findall(r"([A-Za-z_]+)=([^&\x00]+)", text))
                        print("[DEBUG] Parsed KV :", kv)

                        if kv.get('CMD') == 'SET_QUOTA':
                            resp = {'status': 'success', 'message': f"Quota={kv.get('LIMIT')} set for {kv.get('USER')}"}
                            print("[DEBUG] → Executed SET_QUOTA")
                        elif kv.get('CMD') == 'GRANT_ADMIN':
                            resp = {'status': 'success', 'message': f"Admin granted to {kv.get('USER')}"}
                            print("[DEBUG] → Executed GRANT_ADMIN")
                        else:
                            resp = {'status': 'error', 'message': 'Unknown CMD'}

                elif cmd == 'LIST_USERS':
                    if not current_user:
                        resp = {'status': 'error', 'message': 'Not logged in'}
                    else:
                        resp = {'status': 'success', 'online_users': list(self.active_connections), 'all_users': list(self.users)}

                else:
                    resp = {'status': 'error', 'message': 'Unknown command'}

                conn.send(json.dumps(resp).encode())

        except ConnectionResetError:
            pass
        finally:
            if current_user and current_user in self.active_connections:
                del self.active_connections[current_user]
            conn.close()
            print(f"[SERVER] Connection from {addr} closed")

    def start_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(5)
            print(f"[SERVER] Listening on {self.host}:{self.port}")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()


# ---------------------------------------------------------------------------
#                             CLIENT SIDE
# ---------------------------------------------------------------------------
class SecureTextClient:
    def __init__(self, host='localhost', port=12345):
        self.host, self.port = host, port
        self.socket = None
        self.logged_in = False
        self.username = None
        self.running = False

    def connect(self):
        try:
            self.socket = socket.socket()
            self.socket.connect((self.host, self.port))
            return True
        except OSError:
            print("Cannot connect")
            return False

    def send_json(self, obj):
        self.socket.send(json.dumps(obj).encode())
        return json.loads(self.socket.recv(4096).decode())

    @staticmethod
    def _compute_mac_bytes(msg_bytes: bytes) -> str:
        return hashlib.md5(SHARED_KEY + msg_bytes).hexdigest()

    def create_account(self):
        u = input("user: ").strip()
        p = input("pw: ").strip()
        print(self.send_json({'command': 'CREATE_ACCOUNT', 'username': u, 'password': p})['message'])

    def login(self):
        u = input("user: ").strip()
        p = input("pw: ").strip()
        r = self.send_json({'command': 'LOGIN', 'username': u, 'password': p})
        if r['status'] == 'success':
            self.logged_in, self.username, self.running = True, u, True
            threading.Thread(target=self.listen, daemon=True).start()
        print(r['message'])

    def send_message(self):
        to = input("to: ").strip()
        msg = input("msg: ").strip()
        print(self.send_json({'command': 'SEND_MESSAGE', 'recipient': to, 'content': msg})['message'])

    def execute_command(self):
        import binascii
        with open("forged.bin", "rb") as f:
            blob = f.read()

        forged_mac = binascii.hexlify(blob[:16]).decode()
        payload = blob[16:]
        payload_b64 = base64.b64encode(payload).decode()

        print("\n[*] Sending forged admin packet")
        print("    MAC    :", forged_mac)
        print("    Payload:", payload.hex()[:64] + ("…" if len(payload) > 32 else ""))

        r = self.send_json({
            'command': 'EXEC_COMMAND',
            'payload_b64': payload_b64,
            'mac': forged_mac
        })
        print("[SERVER]", r['message'])

        print("DBG client  computed:", self._compute_mac_bytes(payload))
        print("DBG client  forged  :", forged_mac)

    def list_users(self):
        r = self.send_json({'command': 'LIST_USERS'})
        if r['status'] == 'success':
            print("Online:", r['online_users'])
            print("All   :", r['all_users'])
        else:
            print(r['message'])

    def listen(self):
        while self.running:
            try:
                m = json.loads(self.socket.recv(4096).decode())
                if m.get('type') == 'MESSAGE':
                    print(f"\n[{m['timestamp']}] {m['from']}: {m['content']}")
            except:
                break

    def run(self):
        if not self.connect():
            return
        print("SecureText – Flawed MD5 MAC demo")
        while True:
            if not self.logged_in:
                choice = input("1)Create 2)Login 3)Exit> ").strip()
                if choice == '1':
                    self.create_account()
                elif choice == '2':
                    self.login()
                elif choice == '3':
                    break
            else:
                choice = input("1)Msg 2)Cmd 3)List 4)Logout> ").strip()
                if choice == '1':
                    self.send_message()
                elif choice == '2':
                    self.execute_command()
                elif choice == '3':
                    self.list_users()
                elif choice == '4':
                    self.logged_in = False
                    self.running = False
                    self.username = None
                    print("Logged out")

# ---------------------------------------------------------------------------
if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'server':
        SecureTextServer().start_server()
    else:
        SecureTextClient().run()
