# Assignment 3: End-to-End Encryption Implementation

**Course**: ECE572 - Security, Privacy and Data Analytics
**Focus**: Implementing E2EE with ECDH key exchange, AES-GCM encryption, and session management

## Overview

This assignment extends your SecureText application from Assignments 1 and 2 to implement end-to-end encryption (E2EE) with session management. You will implement ECDH key exchange, AES-GCM encryption, and 30-minute session expiration to ensure that messages can only be read by the intended recipient with time-limited security sessions and supporting forward secrecy.

## Learning Objectives

After completing this assignment, you will understand:
- Elliptic Curve Diffie-Hellman (ECDH) key exchange protocol
- Hybrid encryption using ECDH + AES-GCM
- Session management and expiration mechanisms
- End-to-end encryption security properties
- Key management and secure session cleanup
- Integration of cryptographic protocols with existing applications

## Assignment Structure

```
assignment3/
├── README.md
├── report_template.md
├── requirements.txt
└── deliverables/
    └── [Your implementation files]
```

## Technical Requirements

### Cryptographic Requirements

1. **ECDH Key Exchange**
   - Use P-256 curve (secp256r1)
   - Implement proper shared secret derivation
   - Use HKDF-SHA256 for key derivation from shared secret

2. **AES-GCM Encryption**
   - Use AES-256-GCM for authenticated encryption
   - Generate unique nonces for each message
   - Ensure both confidentiality and integrity

3. **Session Management**
   - Implement 30-minute session timeout from last activity
   - Provide 5-minute warning before expiration
   - Secure cleanup of session keys and cryptographic material
   - Activity tracking that resets session timer

### Functional Requirements

1. **End-to-End Encryption**
   - Messages encrypted on sender's device
   - Messages decrypted only on recipient's device
   - Server cannot decrypt message content

2. **Key Management**
   - Secure generation and storage of ECDH key pairs
   - Public key distribution through server
   - Proper handling of key exchange between users

3. **Session Security**
   - Automatic session expiration after 30 minutes of inactivity
   - User warnings before session expiration
   - Forced re-authentication after expiration
   - Secure deletion of expired session data

4. **Integration**
   - Seamless integration with existing SecureText functionality
   - Maintain user authentication from previous assignments
   - Preserve message history and user management features

## Security Properties to Demonstrate

Your implementation must provide:

1. **Confidentiality**: Server cannot read message content
2. **Integrity**: Message tampering is detected
3. **Authentication**: Verify message sender identity
4. **Forward Secrecy**: Session expiration limits compromise impact
5. **Session Security**: Proper timeout and cleanup behavior

## Demonstration Requirements

Your security analysis report must include screenshots and proofs showing:

### 1. E2EE Functionality Proof
- Screenshot of Alice sending encrypted message to Bob
- Screenshot of Bob receiving and decrypting the message
- Database screenshot showing encrypted message content (unreadable)
- Console output showing key exchange process

### 2. Server Cannot Decrypt Proof
- Screenshot of server database with encrypted messages
- Screenshot or console output attempting server-side decryption (should fail)
- Demonstration that server only routes encrypted data

### 3. Session Management Proof
- Screenshot showing active session with remaining time
- Screenshot of 5-minute expiration warning
- Screenshot of session expiration and forced re-authentication
- Console output showing session cleanup process

### 4. Cryptographic Process Proof
- Screenshot of ECDH key generation for two users
- Console output showing shared secret derivation
- Screenshot of AES-GCM encryption process with nonce generation
- Proof that same message produces different ciphertext each time

### 5. Integration Proof
- Screenshot showing E2EE working with existing authentication
- Multiple users exchanging encrypted messages
- Message history with encrypted content
- User management features working alongside E2EE

### 6. Security Properties Verification
- Proof of message integrity (tampering detection)
- Demonstration of forward secrecy through session expiration
- Evidence of secure key cleanup after session timeout

## Report Structure Template

Make sure you include the following sections in your report:

1. **Executive Summary**: Overview of E2EE implementation
2. **Technical Implementation**: ECDH + AES-GCM design and implementation
3. **Session Management**: 30-minute timeout implementation and security
4. **Security Demonstrations**: All required screenshots and proofs mentioned earlier
5. **Threat Analysis**: Security properties and attack resistance
6. **Performance Analysis**: System performance with E2EE enabled
7. **Conclusion**: Lessons learned and future improvements (because this is our final assignment on SecureText)

## Deliverables

1. **Source Code**
   - Complete executable implementation with proper documentation
   - Clean, well-structured code following best practices
   - Integration with existing SecureText functionality

2. **To Include in the Report Template**
   - Technical analysis of E2EE implementation
   - All required screenshots and proofs (see Demonstration Requirements)
   - Security properties demonstration with evidence
   - Session management security assessment
   - Threat analysis and mitigation strategies
   - Implementation design decisions and justifications

3. **Demo Video of Full Secure-Code Working Code**
   - All previous fixes for SecureText
   - End-to-end encrypted messaging demonstration
   - Session expiration and re-authentication
   - Security property verification

**Due Date**: July 31st, 2026 — 11 PM
**Submission**: Submit your completed report on Brightspace with your GitHub repository link
---

**Note on AI use**: If you use an AI tool, disclose it in a `GENAI.md` file in your
deliverables — the prompts you used and which files it touched — and be ready to explain
anything you submit. See the Academic Integrity section of the root README for the full
policy.
