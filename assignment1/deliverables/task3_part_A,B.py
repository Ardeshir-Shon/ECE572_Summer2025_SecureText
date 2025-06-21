#!/usr/bin/env python3
"""
Author: Ardeshir S.
Course: ECE 572; Summer 2025
SecureText Console Messenger
—with bcrypt password hashing, plaintext migration, and a flawed MD5(k||m) MAC
"""
import socket
import threading
import json
import os
import sys
import bcrypt
import hashlib
import base64
from datetime import datetime

SHARED_KEY = b'my_shared_secret_key'


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
                new_h = self._hash_password(pw)
                self.users[uname]['password'] = new_h
                self.users[uname].pop('hash_alg', None)
                migrated = True
            else:
                if 'hash_alg' in data:
                    data.pop('hash_alg')
                    migrated = True
        if migrated:
            print(f"Migrated plaintext passwords to bcrypt")
            self.save_users()

    def _hash_password(self, pw: str, rounds: int = 12) -> str:
        return bcrypt.hashpw(pw.encode('utf-8'),
                             bcrypt.gensalt(rounds=rounds)
                            ).decode('utf-8')

    def _verify_password(self, pw: str, hsh: str) -> bool:
        return bcrypt.checkpw(pw.encode('utf-8'),
                              hsh.encode('utf-8'))

    def _compute_mac_bytes(self, msg_bytes: bytes) -> str:
        return hashlib.md5(SHARED_KEY + msg_bytes).hexdigest()

    def create_account(self, username, password):
        if username in self.users:
            return False, "Username exists"
        ph = self._hash_password(password)
        self.users[username] = {
            'password': ph,
            'created_at': datetime.now().isoformat(),
            'reset_question': 'What is your favorite color?',
            'reset_answer': 'blue'
        }
        self.save_users()
        return True, "Account created"

    def authenticate(self, username, password):
        user = self.users.get(username)
        if not user:
            return False, "Not found"
        if self._verify_password(password, user['password']):
            return True, "OK"
        return False, "Invalid password"

    def reset_password(self, username, new_password):
        if username not in self.users:
            return False, "Not found"
        ph = self._hash_password(new_password)
        self.users[username]['password'] = ph
        self.save_users()
        return True, "Reset OK"

    def handle_client(self, conn, addr):
        print(f"Connection from {addr}")
        current_user = None
        try:
            while True:
                raw = conn.recv(4096)
                if not raw:
                    break
                msg = json.loads(raw.decode('utf-8'))
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
                            self.active_connections[to].send(
                                json.dumps(payload).encode('utf-8')
                            )
                            resp = {'status': 'success', 'message': 'Sent'}
                        else:
                            resp = {'status': 'error', 'message': 'Offline'}

                elif cmd == 'EXEC_COMMAND':
                    if not current_user:
                        resp = {'status': 'error', 'message': 'Not logged in'}
                    else:
                        payload_b64 = msg.get('payload_b64', '')
                        try:
                            payload_bytes = base64.b64decode(payload_b64)
                        except (TypeError, binascii.Error):
                            resp = {'status': 'error', 'message': 'Bad payload encoding'}
                            conn.send(json.dumps(resp).encode('utf-8'))
                            continue

                        client_mac = msg.get('mac', '')
                        computed_mac = self._compute_mac_bytes(payload_bytes)

                        print("[DEBUG SERVER] payload_bytes.hex():", payload_bytes.hex())
                        print("[DEBUG SERVER] client_mac:", client_mac)
                        print("[DEBUG SERVER] computed_mac:", computed_mac)

                        if computed_mac != client_mac:
                            resp = {'status': 'error', 'message': 'MAC bad'}
                        else:
                            text = payload_bytes.decode('latin1')
                            parts = text.split('&')
                            kv = dict(p.split('=', 1) for p in parts if '=' in p)

                            print("[DEBUG SERVER] Parsed KV:", kv)

                            if kv.get('CMD') == 'SET_QUOTA':
                                user = kv.get('USER')
                                lim = kv.get('LIMIT')
                                resp = {'status': 'success',
                                        'message': f"Quota={lim} set for {user}"}
                            elif kv.get('CMD') == 'GRANT_ADMIN':
                                user = kv.get('USER', 'unknown')
                                resp = {'status': 'success',
                                        'message': f"Admin granted to {user}"}
                            else:
                                resp = {'status': 'error', 'message': 'Unknown CMD'}

                elif cmd == 'LIST_USERS':
                    if not current_user:
                        resp = {'status': 'error', 'message': 'Not logged in'}
                    else:
                        resp = {'status': 'success',
                                'online_users': list(self.active_connections),
                                'all_users': list(self.users)}
                else:
                    resp = {'status': 'error', 'message': 'Unknown command'}

                conn.send(json.dumps(resp).encode('utf-8'))

        except ConnectionResetError:
            pass
        finally:
            if current_user in self.active_connections:
                del self.active_connections[current_user]
            conn.close()
            print(f"Connection from {addr} closed")

    def start_server(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(5)
        print(f"Server on {self.host}:{self.port}")
        while True:
            c, a = s.accept()
            t = threading.Thread(target=self.handle_client, args=(c, a))
            t.daemon = True
            t.start()


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
        except:
            print("Cannot connect")
            return False

    def send_json(self, obj):
        self.socket.send(json.dumps(obj).encode('utf-8'))
        return json.loads(self.socket.recv(4096).decode('utf-8'))

    def _compute_mac_bytes(self, msg_bytes: bytes) -> str:
        return hashlib.md5(SHARED_KEY + msg_bytes).hexdigest()

    def create_account(self):
        u = input("user: ").strip()
        p = input("pw: ").strip()
        r = self.send_json({'command': 'CREATE_ACCOUNT',
                            'username': u, 'password': p})
        print(r['message'])

    def login(self):
        u = input("user: ").strip()
        p = input("pw: ").strip()
        r = self.send_json({'command': 'LOGIN',
                            'username': u, 'password': p})
        if r['status'] == 'success':
            self.logged_in, self.username, self.running = True, u, True
            threading.Thread(target=self.listen).start()
        print(r['message'])

    def send_message(self):
        to = input("to: ").strip()
        msg = input("msg: ").strip()
        r = self.send_json({'command': 'SEND_MESSAGE',
                            'recipient': to, 'content': msg})
        print(r['message'])

    def execute_command(self):
        import binascii
        with open("forged.bin", "rb") as f:
            data = f.read()
        forged_mac = binascii.hexlify(data[:16]).decode()
        payload = data[16:]
        payload_b64 = base64.b64encode(payload).decode()

        print("[*] Using forged MAC :", forged_mac)
        print("[*] Payload hex      :", payload.hex())
        print("[DEBUG CLIENT] payload_b64:", payload_b64)

        r = self.send_json({
            'command': 'EXEC_COMMAND',
            'payload_b64': payload_b64,
            'mac': forged_mac
        })
        print(r['message'])

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
                data = self.socket.recv(4096).decode('utf-8')
                m = json.loads(data)
                if m.get('type') == 'MESSAGE':
                    print(f"\n[{m['timestamp']}] {m['from']}: {m['content']}")
            except:
                break

    def run(self):
        if not self.connect():
            return
        print("SecureText w/Flawed MAC (demo)")
        while True:
            if not self.logged_in:
                cmd = input("1)Create 2)Login 3)Exit> ").strip()
                if cmd == '1':
                    self.create_account()
                elif cmd == '2':
                    self.login()
                elif cmd == '3':
                    break
            else:
                cmd = input("1)Msg 2)Cmd 3)List 4)Logout> ").strip()
                if cmd == '1':
                    self.send_message()
                elif cmd == '2':
                    self.execute_command()
                elif cmd == '3':
                    self.list_users()
                elif cmd == '4':
                    self.logged_in = False
                    self.running = False
                    self.username = None
                    print("Logged out")
                else:
                    print("Invalid")


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'server':
        SecureTextServer().start_server()
    else:
        SecureTextClient().run()