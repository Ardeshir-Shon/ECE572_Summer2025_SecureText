#!/usr/bin/env python3
"""
Author: Ardeshir S.
Course: ECE 572; Summer 2025
SecureText Console Messenger
—with bcrypt password hashing, plaintext migration, and a secure HMAC-SHA256
"""

import socket
import threading
import json
import os
import sys
import bcrypt
import hmac
import hashlib
from datetime import datetime


SHARED_KEY = b'my_shared_secret_key'


class SecureTextServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.users_file = 'users.json'
        self.users = self._load_users()
        self._migrate_plaintext_passwords()
        self.active_connections = {}

    def _load_users(self):
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_users(self):
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f, indent=2)

    def _migrate_plaintext_passwords(self):
        migrated = False
        for u, data in list(self.users.items()):
            pw = data.get('password','')
            if not pw.startswith('$2'):
                data['password'] = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
                migrated = True
        if migrated:
            print("[+] Migrated old plaintext passwords to bcrypt")
            self._save_users()

    def _hash_password(self, pw: str) -> str:
        return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

    def _verify_password(self, pw: str, hsh: str) -> bool:
        return bcrypt.checkpw(pw.encode(), hsh.encode())

    def _compute_hmac(self, msg_bytes: bytes) -> str:
        return hmac.new(SHARED_KEY, msg_bytes, hashlib.sha256).hexdigest()

    def _verify_hmac(self, msg_bytes: bytes, mac: str) -> bool:
        return hmac.compare_digest(self._compute_hmac(msg_bytes), mac)


    def create_account(self, username, password):
        if username in self.users:
            return False, "Username exists"
        self.users[username] = {
            'password': self._hash_password(password),
            'created_at': datetime.now().isoformat()
        }
        self._save_users()
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
        self.users[username]['password'] = self._hash_password(new_password)
        self._save_users()
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
                        payload_bytes = msg.get('payload','').encode('latin1')
                        mac = msg.get('mac','')

                        print("[DEBUG SERVER] payload hex:", payload_bytes.hex())
                        print("[DEBUG SERVER] recv  HMAC:", mac)
                        print("[DEBUG SERVER] calc  HMAC:", self._compute_hmac(payload_bytes))

                        if not self._verify_hmac(payload_bytes, mac):
                            resp = {'status': 'error', 'message': 'HMAC bad'}
                        else:
                            text = payload_bytes.decode('latin1')
                            parts = text.split('&')
                            kv = dict(p.split('=',1) for p in parts if '=' in p)
                            if kv.get('CMD') == 'SET_QUOTA':
                                resp = {
                                    'status': 'success',
                                    'message': f"Quota={kv.get('LIMIT')} set for {kv.get('USER')}"
                                }
                            elif kv.get('CMD') == 'GRANT_ADMIN':
                                resp = {
                                    'status': 'success',
                                    'message': f"Admin granted to {kv.get('USER')}"
                                }
                            else:
                                resp = {'status': 'error', 'message': 'Unknown CMD'}

                elif cmd == 'LIST_USERS':
                    if not current_user:
                        resp = {'status': 'error', 'message': 'Not logged in'}
                    else:
                        resp = {
                            'status': 'success',
                            'online_users': list(self.active_connections),
                            'all_users': list(self.users)
                        }

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
        print(f"Server listening on {self.host}:{self.port}")
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=self.handle_client, args=(conn, addr))
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
            print("Connection failed")
            return False

    def send_json(self, obj):
        self.socket.send(json.dumps(obj).encode('utf-8'))
        return json.loads(self.socket.recv(4096).decode('utf-8'))

    def _compute_hmac(self, msg_bytes: bytes) -> str:
        return hmac.new(SHARED_KEY, msg_bytes, hashlib.sha256).hexdigest()

    def create_account(self):
        u = input("user: ").strip()
        p = input("pw: ").strip()
        r = self.send_json({'command':'CREATE_ACCOUNT','username':u,'password':p})
        print(r['message'])

    def login(self):
        u = input("user: ").strip()
        p = input("pw: ").strip()
        r = self.send_json({'command':'LOGIN','username':u,'password':p})
        if r['status']=='success':
            self.logged_in, self.username, self.running = True, u, True
            threading.Thread(target=self.listen, daemon=True).start()
        print(r['message'])

    def send_message(self):
        to = input("to: ").strip()
        msg = input("msg: ").strip()
        r = self.send_json({'command':'SEND_MESSAGE','recipient':to,'content':msg})
        print(r['message'])

    def execute_command(self):
        # Prompt for a structured command
        cmd_str = input("Enter command (e.g. CMD=SET_QUOTA&USER=bob&LIMIT=100): ").strip()
        payload_bytes = cmd_str.encode('latin1')
        mac = self._compute_hmac(payload_bytes)

        print(f"[*] Sending payload: {cmd_str}")
        print(f"[*]  with HMAC: {mac}")

        r = self.send_json({
            'command':'EXEC_COMMAND',
            'payload': cmd_str,
            'mac': mac
        })
        print(r['message'])

    def list_users(self):
        r = self.send_json({'command':'LIST_USERS'})
        if r['status']=='success':
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
        print("SecureText w/ HMAC-SHA256")
        while True:
            if not self.logged_in:
                cmd = input("1)Create 2)Login 3)Exit> ").strip()
                if cmd=='1': self.create_account()
                elif cmd=='2': self.login()
                elif cmd=='3': break
            else:
                cmd = input("1)Msg 2)Cmd 3)List 4)Logout> ").strip()
                if cmd=='1': self.send_message()
                elif cmd=='2': self.execute_command()
                elif cmd=='3': self.list_users()
                elif cmd=='4':
                    self.logged_in = False
                    self.running = False
                    print("Logged out")
                else:
                    print("Invalid")

if __name__ == '__main__':
    if len(sys.argv)>1 and sys.argv[1]=='server':
        SecureTextServer().start_server()
    else:
        SecureTextClient().run()
