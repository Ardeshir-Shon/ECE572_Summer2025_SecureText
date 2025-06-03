# Assignment 1: Security Foundations
**Focus**: Basic security vulnerabilities, password security, and network attacks

## Overview

In this assignment, you will analyze an intentionally insecure messenger application, identify vulnerabilities, demonstrate attacks, and implement security fixes. This assignment establishes the foundation for understanding common security threats and basic cryptographic protections. So in short each assignment follows a three-step workflow for each security challenge:

- Identify the vulnerability in the provided SecureText application

- Implement and demonstrate a realistic attack exploiting that vulnerability

- Fix the vulnerability with a secure implementation

## Learning Objectives

After completing this assignment, you will understand:
- Common security vulnerabilities in applications
- Password storage security (hashing, salting)
- Network eavesdropping and message tampering
- Message Authentication Codes (MACs) and their vulnerabilities
- Length extension attacks on hash-based MACs

## Tasks Overview

### Task 1: Security Vulnerability Analysis
**Objective**: Analyze the provided insecure messenger application and identify security weaknesses.

### Task 2: Securing Passwords at Rest  
**Objective**: Implement secure password storage using hashing and salting techniques.

### Task 3: Network Security and MAC Implementation
**Objective**: Demonstrate network attacks and implement (flawed and secure) message authentication.

---

## Task 1: Security Vulnerability Analysis (25 points)

### Background
You have been provided with a fully functional but intentionally insecure console-based messenger application called "SecureText" (located at `src/securetext.py`). Your task is to analyze this application and identify its security vulnerabilities.

### Requirements

1. **Run and Explore the Application**:
   - Start the server: `python3 src/securetext.py server`
   - Start multiple clients and create accounts
   - Send messages between users
   - Test the password reset functionality

2. **Vulnerability Analysis**:
   Identify and document **at least 5 major security and privacy vulnerabilities** in the application. For each vulnerability:
   - **Describe the vulnerability** and its location in the code
   - **Explain the potential impact** if exploited by an attacker
   - **Reference relevant security principles** from course materials
   - **Categorize the vulnerability** (e.g., authentication, authorization, data protection, etc.)

3. **Attack Scenarios**:
   For each identified vulnerability, describe a realistic client-server attack scenario explaining:
   - What they would need to carry out the attack
   - What they could achieve if successful
   - Final thoughts and consideration

### Deliverables
- **Vulnerability Report**: Detailed analysis of identified weaknesses
- **Attack Scenarios**: Realistic exploitation scenarios

---

## Task 2: Securing Passwords at Rest (25 points)

### Background
The base application stores user passwords in plaintext, making them vulnerable if the user database is compromised. You will implement secure password storage mechanisms.

### Requirements

#### Part A: Password Hashing Implementation

1. **Replace Plaintext Storage**:
   - Modify the `create_account()` method to hash passwords before storing
   - Update the `authenticate()` method to compare hashed passwords
   - Use SHA-256 initially, then discuss its limitations

2. **Implement Slow Hashing**:
   - Research and implement a slow hash function (PBKDF2, bcrypt, scrypt, or Argon2)
   - Justify your choice of hash function and parameters
   - Demonstrate the time difference between fast and slow hashing

#### Part B: Salt Implementation

1. **Add Salt Generation**:
   - Generate a unique random salt for each user (minimum 128 bits)
   - Store the salt alongside the hashed password
   - Modify authentication to use the stored salt

2. **Migration Strategy**:
   - Implement a method to migrate existing plaintext passwords
   - Ensure backward compatibility during the transition

### Attack Demonstration

1. **Dictionary Attack Simulation**:
   - Create a simple dictionary attack against unsalted hashes
   - Show how salting defeats this attack
   - Demonstrate rainbow table protection

2. **Performance Analysis**:
   - Compare cracking times for fast vs. slow hash functions
   - Calculate theoretical brute-force times for your implementation

### Deliverables
- **Updated SecureText**: Version with secure password storage
- **Migration Script**: Tool to upgrade existing plaintext passwords
- **Performance Analysis**: Benchmarks and security analysis
- **Attack Demonstration**: Evidence of protection against common attacks

---

## Task 3: Network Security and Message Authentication (50 points)

### Background
The application sends messages in plaintext over the network, making them vulnerable to eavesdropping and tampering. You will implement and demonstrate these attacks and implement message authentication codes.

### Requirements

#### Part A: Network Attack Demonstrations

1. **Eavesdropping Attack**:
   - Set up network traffic capture using Wireshark or tcpdump
   - Capture and display plaintext messages between users
   - Filter traffic to show only SecureText communication
   - Document the setup and provide evidence (screenshots/logs)

2. **Message Tampering Concept**:
   - Explain how an attacker could intercept and modify messages
   - Describe the tools and techniques needed for active attacks

#### Part B: Flawed MAC Implementation

1. **Implement H(k||m) MAC**:
   - Add a flawed MAC using the construction `MAC(k,m) = MD5(k||m)`
   - Implement shared key distribution (simple pre-shared key is acceptable)
   - Add MAC verification to message processing

2. **Message Format Enhancement**:
   - Modify messages to support commands(by sending a switch as a function input) (e.g., `"CMD=SET_QUOTA&USER=bob&LIMIT=100"`)
   - Ensure the application can process these structured messages as key value format
   - Implement MAC verification for command messages(keep it simple)

#### Part C: Length Extension Attack

1. **Implement Vulnerable MAC**:
   - Implement the flawed MAC construction `MAC(k,m) = MD5(k||m)` exactly as described in course notes
   - Use the Merkle-Damgård construction vulnerability
   - Create a message format that supports commands: `"CMD=SET_QUOTA&USER=bob&LIMIT=100"`

2. **Length Extension Attack Implementation**:
   - Use hash_extender or HashPump tools or implement the length extension attack from scratch to exploit and run the attack
   - Demonstrate the exact attack scenario from course: 
     - Original: `"CMD=SET_QUOTA&USER=bob&LIMIT=100"`
     - Forged: `"CMD=SET_QUOTA&USER=bob&LIMIT=100&padding&CMD=GRANT_ADMIN&USER=attacker"`
   - Show that `MAC(k, original_msg)` can be extended to `MAC(k, forged_msg)` without knowing `k`
**You need to use packet sniffing tools to get the message first and then forge and send.**

#### Part D: Secure MAC Implementation

1. **Replace with Secure MAC**:
   - Implement HMAC-SHA256 or another secure MAC construction
   - Ensure compatibility with existing message format
   - Document why this construction is secure

2. **Security Analysis**:
   - Explain why HMAC resists length extension attacks
   - Compare the security properties of your implementations
   - Discuss key management considerations

### Tools and Setup

#### Network Analysis Setup:
```bash
# Using tcpdump
sudo tcpdump -i lo -A -s 0 port 12345
```

# Using Wireshark
1. Start Wireshark
2. Capture on loopback interface
3. Apply filter: tcp.port == 12345


#### Note that you can extend the hash yourself or use the current open source hash externder tools


### Deliverables
- **Attack Scripts and implementation**: All attacks and exploit scripts should be in the deliverable folder and evidences must be logged and record in the report
- **Network Capture Evidence**: Screenshots and packet captures showing plaintext communication, MAC and Secure MAC
- **Salted and Hashed Implementation**: SecureText version with task 2 fixed code
- **Flawed MAC Implementation**: SecureText version with vulnerable MAC; task 3, part B fixed code
- **Length Extension Attack**: Successful demonstration with evidence
- **Secure MAC Implementation**: Final version with HMAC protection; task 3 part C fixed code
- **Security Analysis**: Comparison of MAC constructions and their properties

---

## Report Requirements

Use the provided `REPORT_TEMPLATE.md` and include all necessary information

### Evidence Requirements
- **Screenshots**: Console outputs, network captures, attack demonstrations
- **Code Snippets**: Key implementation details (not entire files, entire files should be in the forked repo in the proper assignment deliverable)
- **Logs**: Attack outputs, MAC verification results
- **Performance Data**: Hash timing comparisons and other relevant information

## Other Useful Info

**Install Required Tools**:
   ```bash
   # Install network analysis tools
   sudo apt-get install wireshark tcpdump  # Linux
   ```

## Important Notes

- **Start Early**: Network setup and attack demonstrations can be time-consuming
- **Document Everything**: Take screenshots and save logs as you work
- **Test Thoroughly**: Ensure your implementations work before moving to the next task
- **Security First**: Consider the implications of each vulnerability and fix

## Common Issues and Solutions

### Network Capture Problems
- **Permission denied**: Use `sudo` for tcpdump or run Wireshark as admin
- **No traffic captured**: Check loopback interface and correct port numbers
- **Encrypted traffic**: Ensure you're analyzing the unmodified base application

### Implementation Problems
- **Socket errors**: Check port availability and firewall settings
- **Authentication failures**: Verify hash/salt implementation consistency

---

**Due Date**: June 18th, 2025
**Submission**: Submit your completed report on Brightspace with your GitHub repository fork link

In this assignment series security vulnerabilities are everywhere - your job is to find them, attack and fix them systematically.

Good luck!
