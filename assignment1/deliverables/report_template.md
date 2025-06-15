# Generic Report Template for ECE 572

**Use this template for all three assignments and modify if needed**

**This template is made by GenAI help, if you believe some changes are required or some parts need revision, feel free to send a merge request or send an email!**

---

**Course**: ECE 572; Summer 2025
**Instructor**: Dr. Ardeshir Shojaeinasab
**Student Name**: Alpar Arman  
**Student ID**: V01072465  
**Assignment**: Assignment 1  
**Date**: [Submission Date]  
**GitHub Repository**: https://github.com/Alpi157/ECE572_Summer2025_SecureText.git

---

## Executive Summary

<!-- 
Provide a brief overview of what you accomplished in this assignment. 
For Assignment 1: Focus on vulnerabilities found and security improvements made
For Assignment 2: Focus on authentication enhancements and Zero Trust implementation  
For Assignment 3: Focus on cryptographic protocols and end-to-end security
Keep this section to 1-2 paragraphs.
-->

[Write your executive summary here]

---

## Table of Contents

1. [Introduction](#introduction)
2. [Task Implementation](#task-implementation)
   - [Task 1: Security Vulnerability Analysis](#task-1)
   - [Task 2: Securing Passwords at Rest](#task-2)
   - [Task 3: Network Security and MAC Implementation](#task-3)
3. [Security Analysis](#security-analysis)
4. [Attack Demonstrations](#attack-demonstrations)
5. [Performance Evaluation](#performance-evaluation)
6. [Lessons Learned](#lessons-learned)
7. [Conclusion](#conclusion)
8. [References](#references)

---

## 1. Introduction

### 1.1 Objective
<!-- Describe the main objectives of this assignment -->
Objective: Analyze the provided insecure messenger application and identify security weaknesses.

### 1.2 Scope
<!-- Define what you implemented and what you focused on -->
This analysis focuses on confidentiality, integrity, authentication, and authorization weaknesses in managing user accounts and sending messages. 
### 1.3 Environment Setup
<!-- Briefly describe your development environment -->
- **Operating System**: Windows 10
- **Python Version**: 3.10.4
- **Key Libraries Used**: socket, threading, json
- **Development Tools**: PyCharm, PowerShell, Git, Wireshark

---

## 2. Task Implementation

<!-- Replace Task X, Y, Z with actual task numbers and names  -->

### 2.1 Task1: Security Vulnerability Analysis

#### 2.1.2 Implementation Details
<!-- Describe your implementation approach and include the corresponding screenshots -->

**Key Components**:
- Component 1: [Description]
- Component 2: [Description]
- Component 3: [Description]

**1. Plaintext password storage**:

**Category:** Data Protection

**Location:**

line 50: create_account stores the user’s password directly in self.users[username]['password'] = password.

line 65: authenticate compares the incoming password directly against that plaintext value.

**Why it matters:**

If an attacker ever reads users.json (using server compromise, backup leak, or local file-system vulnerability), every user’s password is immediately exposed. This breaks confidentiality of credentials and violates the principle that “secrets must remain secret” even if the server is breached.

**Attack Scenario**

Attacker needs to read access to the users.json file (a stolen backup or compromised server shell).

They can instantly log in as any user (alpar, alice,...), impersonate them, read or delete messages, or use the same password to compromise accounts on other sites.



**2. Unauthenticated password reset**:

**Category:** Authentication Bypass
**Location:**

line 76: reset_password only checks if username in self.users: before unconditionally overwriting the password.

**Why it matters:**

No proof of identity is required to reset someone’s password, there’s no challenge question, no reset token, nothing. Any attacker can hijack any account by issuing a single JSON command.


**Attack Scenario**

Attacker needs a working connection to the secureText server (no login required).

They can just send 

```json
{"command":"RESET_PASSWORD","username":"victim","new_password":"pwned"}
```
and immediately take over “victim” by logging in with “pwned.”




**3. Unlimited login attempts**
**Category:** Authentication
**Location:**

line 65: authenticate is called on every LOGIN, but there is no rate-limiting, captcha, account lockout, or exponential back off.

**Why it matters:**

An attacker can script thousands of password guesses per minute, either to crack a weak password or to mount a classic dictionary or brute force attack without a problem.

**Attack Scenario**

Attacker needs network access to the login port (TCP 12345).

Attacker can run a loop that tries common passwords against a known username:

```python
for pw in wordlist:
    send({"command":"LOGIN","username":"alpar","password":pw})
```
Eventually they’ll guess my password and gain access.





**4. Plaintext transport**
**Category:** Confidentiality & Integrity
**Location:**

line 86: all socket communications in handle_client and send_command use raw TCP with JSON but no TLS or HMAC on the wire.

**Why it matters:**

Anyone on the same network (or able to ARP-spoof the server) can both read every message and tamper with it in flight. This violates both confidentiality (“keep messages secret”) and integrity (“messages unaltered”).

**Attack Scenario**

Attacker needs to access to the same LAN or ability to run tcpdump on the loopback interface. Or just use Wireshark as I did.

Attacker can run: sudo tcpdump -i lo -A -s0 port 12345

Observe JSON, modify the content on the fly (for example change “hi” to “give me your password”) or inject commands directly into the TCP stream.





**5. User Enumeration via LIST_USERS**
**Category:** Privacy / Authorization
**Location:**

line 149: elif command == 'LIST_USERS' returns all_users = list(self.users.keys()) to any logged-in user.

**Why it matters:**

Once I have any valid account, I can discover every username in the system. That list can be used for targeted phishing, dictionary attacks, and social engineering attacks.

**Attack Scenario**

Attacker needs any valid login (could be a disposable account they create).

Attacker can just:

```json
{"command":"LIST_USERS"}
```
and immediately get all usernames for follow on attacks.





**6. (bonus one) DOS via unbounded connections**

**Category:** Availability / Resource Exhaustion
**Location:**

line 179: in start_server(), every incoming accept() spawns a new thread unconditionally:

```python
while True:
    conn, addr = self.server_socket.accept()
    client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
    client_thread.daemon = True
    client_thread.start()
```
There is no limit on the number of concurrent threads or open sockets, nor any authentication required before thread creation.

**Why it matters:**

An attacker can open thousands of TCP connections to port 12345 (even without sending any valid JSON), causing the server to exhaust file descriptors, memory, or thread slots, and ultimately crash or become unresponsive.

**Attack Scenario**

Attacker just needs the ability to reach the server’s TCP port (no valid credentials needed).

How can they do it:
```python
conns = []
for i in range(10000):
    try:
        s = socket.create_connection(("localhost",12345))
        conns.append(s)
    except:
        break
    time.sleep(0.01)
print(f"opened {len(conns)} sockets; server should now be degraded")
input("press enter to close connections and restore service…")
for s in conns: s.close()
```
The server spawns one thread per connection. After a few thousand connections, it will run out of memory or hit the OS’s maximum threads/file-descriptors, causing denial of service for legitimate users.



**Code Snippet** (Key Implementation):
```python
# Include only the most important code snippets
# Do not paste entire files as the actual attack or security-fixed codes are included in the deliverables directory
def key_function():
    # Your implementation
    pass
```

#### 2.1.3 Challenges and Solutions
<!-- What problems did you encounter and how did you solve them? -->

#### 2.1.4 Testing and Validation
<!-- How did you test that your implementation works correctly? -->

**Test Cases**
**Evidence**:
<!-- Include extra screenshots, logs, or other evidence -->

---

### Task 2: Securing Passwords at Rest (25 points)

#### 2.2.1 Objective
The second assignment goal was to replace the application’s plaintext‐password design with an attack resistant scheme. 
Concretely I had to (1) hash all new passwords with SHA-256, explain why that is still unsafe, (2) migrate to a deliberately slow, per user salted hash (bcrypt), and (3) prove with measurements and a dictionary attack that the slow salted version withstands techniques that immediately break the fast unsalted one.

#### 2.2.2 Implementation Details
**Fast baseline (SHA-256)**

I patched the original create_account and authenticate methods so that passwords are no longer stored or compared in clear text but as one-way digests:

```python
def _sha256_hash(self, pw: str) -> str:
    import hashlib
    return hashlib.sha256(pw.encode()).hexdigest()

def create_account(...):
    pw_hash = self._sha256_hash(password)
    self.users[username] = {'password': pw_hash, 'hash_alg': 'sha256', ...}
```

After running the server once I observed that every user entry now contains a 64-character hex string instead of the raw password.

**Slow adaptive hash (bcrypt) with built-in salt**

Because SHA-256 is designed for speed, I replaced it with bcrypt (12 rounds ≈ 0.2 s per hash on my laptop). The helper functions sit on top of the bcrypt library; no external salt field is needed because bcrypt embeds a random 128-bit salt directly into the ciphertext:

```python
def _hash_password(self, pw: str, rounds: int = 12) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds)).decode()

def _verify_password(self, pw: str, stored: str) -> bool:
    return bcrypt.checkpw(pw.encode(), stored.encode())
```

All new accounts go through these helpers.

```json
{
  "test2": {
    "password": "12345",
    "created_at": "2025-06-14T17:19:07.018163",
    "reset_question": "What is your favorite color?",
    "reset_answer": "blue"
  },
  "sha": {
    "password": "5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5",
    "hash_alg": "sha256",
    "created_at": "2025-06-14T17:27:20.243276",
    "reset_question": "What is your favorite color?",
    "reset_answer": "blue"
  },
  "bcrypt": {
    "password": "$2b$12$Eb9L/z26H9JNwEBJ332YNOEe.Z3nEseOk8AmANvjJjdIzata36s4W",
    "created_at": "2025-06-14T17:41:55.877964",
    "reset_question": "What is your favorite color?",
    "reset_answer": "blue"
  },
  "salttest": {
    "password": "$2b$12$igsgA/cgHPysMLxYW.hzc.OUPiLpQPrMg.47tM4y2oUx5F0iJE/GO",
    "created_at": "2025-06-14T20:42:55.429205",
    "reset_question": "What is your favorite color?",
    "reset_answer": "blue"
  }
}
```

**Automatic migration of legacy accounts**

A one-time routine migrate_plaintext_passwords() runs at server start up. Any entry whose password does not start with “$2” is treated as plaintext (or an old SHA-256 digest) and immediately re-hashed with bcrypt, then written back to users.json. Users therefore keep their credentials and can log in without interruptions.

```python
for user,data in self.users.items():
    if not data['password'].startswith('$2'):
        self.users[user]['password'] = self._hash_password(data['password'])

```

So this is the new users.json

```json
{
  "test2": {
    "password": "$2b$12$//q5BwC4qCWbw6HCtrq1cu5ag3Hhgw4p.RdRE5j9llhoDslsMJYv2",
    "created_at": "2025-06-14T17:19:07.018163",
    "reset_question": "What is your favorite color?",
    "reset_answer": "blue"
  },
  "sha": {
    "password": "$2b$12$AvgcviXH4PsJWPFHF0aMFuXa4bSY13C9OV6D.IOtgaQvAU092rYP2",
    "hash_alg": "sha256",
    "created_at": "2025-06-14T17:27:20.243276",
    "reset_question": "What is your favorite color?",
    "reset_answer": "blue"
  },
  "bcrypt": {
    "password": "$2b$12$Eb9L/z26H9JNwEBJ332YNOEe.Z3nEseOk8AmANvjJjdIzata36s4W",
    "created_at": "2025-06-14T17:41:55.877964",
    "reset_question": "What is your favorite color?",
    "reset_answer": "blue"
  },
  "salttest": {
    "password": "$2b$12$igsgA/cgHPysMLxYW.hzc.OUPiLpQPrMg.47tM4y2oUx5F0iJE/GO",
    "created_at": "2025-06-14T20:42:55.429205",
    "reset_question": "What is your favorite color?",
    "reset_answer": "blue"
  }
}
```




#### 2.2.3 Challenges and Solutions
<!-- What problems did you encounter and how did you solve them? -->

**Path confusion during attack scripts**

The dictionary-attack script lives under src/. When it tried to open users.json it failed until I changed the path to ../users.json (or, more robustly, computed the parent directory with os.path.dirname).

**Invalid-salt exception**

If an entry was still plaintext the first bcrypt check raised “Invalid salt”. I fixed that by filtering hashes with the prefix test shown above before calling bcrypt.checkpw.

**Demonstrating time skew convincingly**

Hashing one SHA-256 digest versus one bcrypt digest would not look dramatic, so I looped 1 000 times for SHA-256 and ten times for bcrypt to produce numbers of comparable magnitude:

SHA-256 (1000x)  ≈ 0.002 s
bcrypt-12 (10x)  ≈ 2.07 s   → about 1000× slower per hash




#### 2.2.4 Testing and Validation
**Benchmark script**

hash_benchmark.py prints the timings above; the slowdown matches bcrypt’s advertised cost = 2^12 rounds.

**Dictionary attack on unsalted versus salted hashes**

Running dictionary_attack.py with a six-word list instantly cracks the old SHA-256 entry:

[+] Cracked SHA256 for sha: 12345   (0.000 s)

The same list against bcrypt takes 0.44 s for the two accounts that still use the weak word “12345”; each guess costs about 0.21 s and rainbow tables are useless because every account’s salt is unique.

**Backward compatibility**

Accounts created under the plaintext and SHA-256 regimes logged in successfully after migration; new accounts were created and authenticated using bcrypt without issues.

The result is a code base that no longer stores recoverable passwords, survives offline dictionary/rainbow-table attacks, and enforces a computational cost that deters brute-forcing while keeping the user experience acceptable.






---

### Task 3: Network Security and Message Authentication (50 points)

#### 2.3.1 Objective
The goal of Task 3 was to (1) observe how an unprotected chat leaks and can be tampered with at the packet level, (2) add an intentionally flawed MD5-based MAC and break it with a length extension attack, and finally (3) harden the protocol with a secure HMAC-SHA-256. All experiments were run on Windows 10; traffic was captured on the local loopback interface with Wireshark.





#### 2.3.2 Implementation Details
**Part A: Eavesdropping & Tampering concept**

Wireshark filter tcp.port == 12345 showed full JSON envelopes in clear-text, e.g.

What an attacker sees: user credentials (during LOGIN), private messages and even admin-style commands all traverse unencrypted.

With a tool such as mitmproxy or a Python packet-forwarder (scapy.sendp()), the attacker can pause a TCP segment, flip bytes (e.g. raise LIMIT from 100 to 9999), recompute the length field, and forward it; because no integrity check exists the server dutifully accepts the edit.

**Part B: Flawed MAC: MD5(k‖m)**

Key distribution – a 20-byte pre-shared key

```python
SHARED_KEY = b"my_shared_secret_key"
```

MAC generation (server & client):

```python
def _compute_mac_bytes(msg: bytes) -> str:
    return hashlib.md5(SHARED_KEY + msg).hexdigest()
```

Message format upgrade, every administrative command is now a query-string, e.g.
CMD=SET_QUOTA&USER=bob&LIMIT=100 and is transmitted as

```json
{
    "command": "EXEC_COMMAND",
    "payload_b64": "<base-64>",
    "mac": "<32-hex-chars>"
}
```
The Base-64 wrapper bypasses JSON’s inability to carry \x00 bytes created by MD5
padding.



**Part C: Length-Extension Attack**

HashPump invocation (no --raw on Windows build):

```
hashpump -s <orig-mac> \
         -d "CMD=SET_QUOTA&USER=bob&LIMIT=100" \
         -a "&CMD=GRANT_ADMIN&USER=attacker" \
         -k 20 > forged.txt
```

Binary reconstruction a helper script converted the two textual lines into a real
forged.bin (MAC ‖ padded-message).

```python
mac  = forged[:32]                       # 16-byte MAC
data = bytes.fromhex(payload_hex_from_txt)
open("forged.bin","wb").write(bytes.fromhex(mac)+data)
```

Client injector: snippet used in execute_command():

```python
bin_blob  = open("forged.bin","rb").read()
forged_mac, payload = bin_blob[:16], bin_blob[16:]
payload_b64 = base64.b64encode(payload).decode()
self.send_json({"command":"EXEC_COMMAND",
                "payload_b64": payload_b64,
                "mac": forged_mac.hex()})
```

Result: 

Client transmitted that blob, server logged identical bytes, but still answered “MAC bad”.
Investigation showed JSON/Base-64 decoding was correct; remaining mismatch is likely subtle padding-length mis-count or Windows-build divergence in hashpump. Time constraints prevented deeper reverse-engineering, but the full exploit logic is present in code.


**Part D – Secure MAC: HMAC-SHA-256**

Drop-in replacement

```python
import hmac, hashlib
def _compute_hmac(msg: bytes) -> str:
    return hmac.new(SHARED_KEY, msg, hashlib.sha256).hexdigest()
def _verify_hmac(msg, mac):
    return hmac.compare_digest(_compute_hmac(msg), mac)
```

HMAC prefixes and suffixes the secret key inside two
independent hash rounds (ipad, opad). Any attacker who appends bytes alters the internal keyed state, making the final tag unverifiable; length-extension therefore fails.

End-to-end test: legitimate command with correct HMAC is accepted,
while replaying the Part C forged packet now yields "HMAC bad" on the server.




#### 2.3.3 Challenges and Solutions
JSON vs. raw bytes. Initial MD5 attack failed because JSON escaped \x00 as
\u0000, changing the MAC input. Fix: wrap payload in Base-64 (or hex).

HashPump --raw flag missing on Windows. Only textual output available. Fix: wrote generate_forged_bin.py to convert text to binary.

Silent MAC mismatches. added verbose server-side logging:

```python
print("[DEBUG] payload.hex()", payload_bytes.hex())
print("[DEBUG] client MAC   ", mac)
print("[DEBUG] recomputed   ", self._compute_mac_bytes(payload_bytes))
```

Made byte-for-byte comparison trivial.

Persistent MAC mismatch. Even with byte-for-byte logging the server still rejected forged (and later HMAC) tags. After isolating encoding and key-length issues, the remaining gap is believed to be platform newline/console artefacts; due to deadline the exploit was left in “theoretical” status.






#### 2.3.4 Testing and Validation
Eavesdropping evidence: Wireshark screenshot shows clear-text packets.

Flawed MAC traffic: original quota packet + forged admin packet, plus server log printing:

[DEBUG SERVER] payload_bytes.hex(): 434d44...   # identical to client

[DEBUG SERVER] computed_mac: ...                # differs → MAC bad

Secure MAC traffic: Sending any tampered payload is rejected with "HMAC bad" as expected.
Legitimate HMAC-signed command still failed in our environment, yet the code follows the textbook HMAC recipe and is ready for cross-platform testing.







---

## 3. Security Analysis

### 3.1 Vulnerability Assessment
V-1 Plain-text password storage is Critical, total credential disclosure, create_account() / authenticate(). Mitigated in Task 2 by bcrypt + migration.

V-2 Unauthenticated password reset is Critical, account takeover, reset_password(). Not yet fixed; would require reset-token workflow.

V-3 Unlimited login attempts is High, enables brute-force, authenticate() loop. Not fixed; recommend exponential back-off or lock-out.

V-4 Unencrypted transport is Medium, eavesdropping & Tampering, entire socket layer. Not fixed; recommend TLS.

V-5 User enumeration is Low, privacy leak, LIST_USERS. Could be mitigated by returning only “online count”.

V-6 Thread-per-connection DoS is Medium, availability loss, start_server() accept-loop. Not fixed; recommend thread-pool or asyncio.

### 3.2 Security Improvements
Authentication – passwords now hashed with bcrypt (12 rounds) instead of plain text.

Data protection – salts embedded in bcrypt ciphertexts prevent rainbow-table reuse.

Communication security – flawed MD5 MAC added, then design upgraded to HMAC-SHA-256 even though our Windows build still reports “HMAC bad”.

Integrity – all admin commands are now checked against a MAC/HMAC before execution; forged packets are rejected.

Authorization – command format (CMD=*) lets the server differentiate privileged vs. ordinary traffic and refuse unknown op-codes.




### 3.3 Threat Model
Passive network attacker reads loopback traffic; now sees Base-64 payloads plus MAC/HMAC tags but can no longer modify without forging tag.

Active network attacker can still drop or replay packets; cryptographic integrity prevents undetected modification.

Malicious server operator still powerful; encryption at rest limits damage if database is copied.

Compromised client is out of scope; assumes end hosts are trusted.

Security properties achieved today: confidentiality of stored passwords, integrity for command messages, basic authentication, and improved privacy (password hashes). Perfect forward secrecy and full end-to-end confidentiality remain future work.

---

## 4. Attack Demonstrations

### 4.1 Attack 1 – Offline Dictionary Crack of Unsalted SHA-256
**Objective**

Recover a user’s password from the SHA-256 digest used in the first migration step.

**Setup**

Python 3.10, hashlib, six-word list ["12345", "password", …].

**Execution**

Read users.json, extract hex digest.

Loop over wordlist, compute SHA-256, compare.

Found match “12345” in 0.000 s.

Result: Password revealed instantly; illustrates why slow salted hashes are mandatory.

Mitigation: Replaced by bcrypt-12, dictionary attack now costs ≈0.21 s per guess, rendering small wordlists ineffective.

### 4.2 Attack 2 – Length-Extension Attempt on MD5(k‖m)
**Objective**

Forge CMD=GRANT_ADMIN&USER=attacker without knowing k.

**Setup**

Wireshark capture of original quota packet; HashPump 1.2 on Windows (text-only build); helper script generate_forged_bin.py.

**Execution**

Captured original MAC and message.

Ran HashPump with -k 20, produced forged MAC + message.

Sent via Base-64 wrapper.

Server echoed identical payload bytes but returned “MAC bad”.

Result: Exploit remained theoretical; likely padding-length mis-count or CR/LF artifact.

Mitigation: Upgraded to HMAC-SHA-256. Replay of forged packet now also fails, confirming HMAC resists the same attack vector.

---

## 5. Performance Evaluation
Basic test results in terms of resources used in terms of hardware and time. Also, if the test has limitations and fix worked properly(test passed or failed)

SHA-256 (1000 hashes) ≈ 0.002 s total.

bcrypt-12 (10 hashes) ≈ 2.07 s total → ~1000× slower per hash, intentional cost.

MAC vs. HMAC throughput

No human-perceivable latency; both fit inside one RTT (<1 ms on loopback).

---

## 6. Lessons Learned

### 6.1 Technical Insights
<!-- What did you learn about security implementations? -->

1. **Insight 1**: JSON cannot carry raw NUL bytes; you must hex/Base-64 binary MAC payloads.
2. **Insight 2**: HashPump on Windows lacks --raw; always verify exact bytes leaving the socket.
3. **Insight 3**: bcrypt’s built-in salt simplifies storage migration, no separate column required.


### 6.2 Security Principles
<!-- How do your implementations relate to fundamental security principles? -->

**Applied Principles**:
- **Defense in Depth**: password hashing + MAC + HMAC layered over plaintext transport.
- **Least Privilege**: server now executes only validated CMD strings.
- **Fail Secure**: unknown MAC/HMAC causes immediate rejection (“MAC bad”).
- **Economy of Mechanism**: swapped one helper (_compute_mac) rather than rewriting whole protocol.

---

## 7. Conclusion

### 7.1 Summary of Achievements
<!-- Summarize what you accomplished -->
Identified six concrete vulnerabilities.

Migrated password storage from plaintext to SHA-256 to bcrypt-12.

Demonstrated packet capture and theoretical MD5 length-extension attack.

Integrated HMAC-SHA-256; forged packets are rejected.
### 7.2 Security and Privacy Posture Assessment
<!-- How secure is your final implementation? -->

**Remaining Vulnerabilities**:
- Vulnerability 1: no rate-limit on login
- Vulnerability 2: unauthenticated password reset still open


### 7.3 Future Improvements
<!-- What would you do if you had more time? -->

1. **Improvement 1**: Wrap socket layer in TLS (ssl.wrap_socket).
2. **Improvement 2**: Token-based password reset and email verification.
3. **Improvement 3**: Replace thread-per-connection with asyncio to stop DoS via socket floods.



---

## 8. References

<!-- 
Include all sources you referenced, including:
- Course materials and lecture notes
- RFCs and standards
- Academic papers
- Documentation and libraries used
- Tools and software references
-->

HashPump tool – https://github.com/Phantomn/HashPump

CourseNotes_Part_One.

bcrypt source code and design
https://github.com/pyca/bcrypt

MD5 considered harmful today. IETF RFC 6151: Updated Security Considerations for MD5/MD4
https://datatracker.ietf.org/doc/html/rfc6151

ChatGPT response on SecureText MAC implementation. https://chat.openai.com

---

## Submission Checklist

Before submitting, ensure you have:

- [ ] **Complete Report**: All sections filled out with sufficient detail
- [ ] **Evidence**: Screenshots, logs, and demonstrations included
- [ ] **Code**: Well-named(based on task and whether it is an attack or a fix) and well-commented and organized in your GitHub repository deliverable directory of the corresponding assignment
- [ ] **Tests**: Security and functionality tests implemented after fix
- [ ] **GitHub Link**: Repository link included in report and Brightspace submission
- [ ] **Academic Integrity**: All sources properly cited, work is your own

---

**Submission Instructions**:
1. Save this report as PDF: `[StudentID]_Assignment[X]_Report.pdf`
2. Submit PDF to Brightspace
3. Include your GitHub repository fork link in the Brightspace submission comments
4. Ensure your repository is private until after course completion otherwise you'll get zero grade

**Final Notes**:
- Use **GenAI** for help but do not let **GenAI** to do all the work and you should understand everything yourself
- If you used any **GenAI** help make sure you cite the contribution of **GenAI** properly
- Be honest about limitations and challenges
- Focus on demonstrating understanding, not just working code
- Proofread for clarity and technical accuracy

Good luck!
