# Assignment 2: Advanced Authentication and Authorization
**Focus**: Multi-factor authentication, OAuth integration, and Zero Trust principles

## Overview

Building on Assignment 1's foundation, you will now implement advanced authentication mechanisms and authorization controls. This assignment explores modern authentication patterns, multi-factor authentication, and Zero Trust security principles.

## Learning Objectives

After completing this assignment, you will understand:
- Multi-factor authentication (MFA) implementation and security benefits
- OAuth 2.0 integration for third-party authentication
- Time-based One-Time Passwords (TOTP) and their cryptographic foundation
- Zero Trust security model and its practical implementation
- Challenge-response authentication protocols
- Authentication factor categories and their security implications

## Tasks Overview

### Task 4: Multi-Factor Authentication with TOTP
**Objective**: Implement Time-based One-Time Passwords to strengthen authentication.

### Task 5: OAuth Integration
**Objective**: Add third-party authentication using OAuth 2.0 protocols.

### Task 6: Challenge-Response Authentication & Zero Trust
**Objective**: Implement challenge-response protocols and Zero Trust principles.

---

## Task 4: Multi-Factor Authentication with TOTP (40 points)

### Background
Passwords alone are vulnerable to various attacks (phishing, database breaches, credential stuffing). Multi-factor authentication adds additional security layers by requiring multiple forms of verification.

### Requirements

#### Part A: TOTP Implementation

1. **Base TOTP Setup**:
   - Install and use the `pyotp` library for TOTP generation
   - Generate unique TOTP secrets for each user during account creation
   - Store TOTP secrets securely (encrypted or hashed appropriately)
   - Implement TOTP verification during login process

2. **QR Code Generation**:
   - Generate QR codes for easy setup with authenticator apps
   - Include proper TOTP URI format: `otpauth://totp/SecureText:username?secret=BASE32SECRET&issuer=SecureText`
   - Display QR codes in ASCII art format for console compatibility
   - Use the `qrcode` library with appropriate error correction

3. **Enhanced Authentication Flow**:
   ```
   Traditional: Username + Password
   Enhanced: Username + Password + TOTP Code
   ```

#### Part B: Security Analysis and Attack Demonstrations

1. **Demonstrate Authentication Bypass**:
   - Simulate a scenario where passwords are compromised but TOTP protects the account
   - Document the additional security provided by the second factor

2. **TOTP Security Analysis**:
   - Analyze the cryptographic foundation of TOTP (HMAC-SHA1, time windows)
   - Discuss time synchronization issues and tolerance windows
   - Examine backup code implementation for recovery scenarios

3. **Attack Vectors and Mitigations**:
   - Research and discuss SIM swapping attacks (relevant for SMS-based 2FA)
   - Compare TOTP apps vs. SMS-based 2FA security
   - Analyze phishing resistance of different 2FA methods

#### Part C: User Experience Considerations

1. **Security vs. Usability**:
   - Implement rate limiting for TOTP attempts
   - Add time window tolerance for clock skew
   - Provide helpful error messages without leaking information

---

### Deliverables
- **TOTP-Enhanced SecureText**: Version with 2FA authentication
- **QR Code Generation**: Console-based QR code display for authenticator setup
- **Security Analysis**: Comparison of authentication methods and attack resistance

---

## Task 5: OAuth Integration (35 points)

### Background
OAuth 2.0 allows users to authenticate using existing accounts (e.g., GitHub) without sharing passwords. This reduces the risk of password reuse and leverages the security of trusted identity providers. Although OAuth is often implemented in web applications, this task guides you through integrating OAuth authentication in a **console-based system** using a simplified flow.

---

### Requirements

####  Part A: Console-Compatible OAuth 2.0 Implementation

1. **Choose an OAuth Provider**:
   - Use **GitHub** as the OAuth provider for this task.
   - Register your application to obtain a **Client ID** and **Client Secret** from [GitHub Developer Settings](https://github.com/settings/developers).
   - Set your redirect URI to a placeholder like `http://localhost`.

2. **Console-Based OAuth Login**:
   - Launch the authorization URL in the user’s default browser using Python.
   - Ask the user to **copy-paste the full redirect URL** they are sent to after login.
   - Parse the URL to extract the **authorization code** and **state** parameters.
   - Exchange the code for an access token via a POST request to GitHub.

3. **User Info Extraction**:
   - Use the access token to query GitHub’s API (e.g., `/user`, `/user/emails`).
   - Display the authenticated GitHub username to the user.

4. **Hybrid Authentication**:
   - Support login via both:
     - Local accounts (username + password)
     - GitHub OAuth
   - If a GitHub user matches an existing local user (e.g., same email), link the accounts or create a new linked user record.
   - Handle username conflicts with appropriate warnings or suggestions.

---

#### Part B: Security Features

1. **Secure OAuth Flow**:
   - Generate and validate a random **`state`** parameter to prevent CSRF.
   - **PKCE is optional** for this assignment but can be attempted for bonus.
   - Do not store access tokens persistently; treat sessions as short-lived.
   - Clearly separate OAuth sessions from local account sessions.

2. **Session Handling**:
   - After successful GitHub login, store the session (e.g., using in-memory flags).
   - Implement logout functionality for OAuth users (e.g., remove session).
   - Gracefully handle expired or missing tokens (e.g., show error or re-authenticate).

---

#### Part C: Security Analysis

1. **Benefits of OAuth Authentication**:
   - Describe how OAuth reduces the risks associated with passwords (reuse, leakage).
   - Analyze the trade-offs of using a third-party identity provider (e.g., GitHub trust).

2. **Known OAuth Vulnerabilities**:
   - Research and document common attack vectors:
     - Authorization code interception
     - Missing or invalid `state` parameters
     - Redirect URI manipulation
     - Token leakage
   - Explain **how your simplified console-based implementation mitigates** (or is vulnerable to) each one.

---


### Deliverables

- **OAuth-Integrated SecureText**: Console-based version supporting GitHub OAuth authentication via browser and manual code entry.
- **Provider Configuration**: Instructions for registering a GitHub OAuth application and setting up client credentials.
- **Security Analysis**: Brief report discussing OAuth benefits, known vulnerabilities, and how your implementation mitigates them.
- **Hybrid Authentication**: Working support for both local (username/password) and OAuth (GitHub) accounts, with optional account linking or conflict handling.

---

## Task 6: Zero Trust Implementation (40 points)

### Background
Zero Trust is a modern security model based on the principle of "never trust, always verify." It assumes that every user and device must be continuously authenticated, authorized, and validated — even if they are already inside the network. This task explores practical Zero Trust ideas in the context of your SecureText messenger.

---

### Requirements (Console-Compatible)

---

### Part A: Challenge-Response Authentication (10 points)

1. **Basic Challenge-Response**:
   - Implement a simple challenge-response mechanism: `MAC(k, c)`
   - Server sends a random challenge string `c`
   - Client returns `HMAC(k, c)` using a shared secret `k`
   - Verify response on the server before allowing login

2. **TOTP as Challenge-Response**:
   - Show how TOTP is a time-based version where `c = current_time / 30`
   - Briefly compare advantages of TOTP vs basic challenge-response (e.g., replay protection, synchronization)

---

### Part B: Role-Based Access Control (RBAC) and Session Security (15 points)

1. **User Roles**:
   - Define roles: `user`, `admin`
   - Store role info per user in the user database (e.g., in `users.json`)
   - Allow or restrict commands based on role
     - Example: Only `admin` can use `LIST_USERS` or reset others’ passwords

2. **Session Management**:
   - Implement session timeouts based on time (e.g., 5 minutes of inactivity) or number of actions (e.g., auto-logout after 10 commands)
   - Require password re-entry or TOTP for sensitive operations (e.g., password reset or access to logs)

---

### 🔹 Part C: Logging and Basic Monitoring (15 points)

1. **Action Logging**:
   - Log authentication attempts (successful and failed)
   - Log user commands with timestamp and outcome
   - Log role-based access attempts (e.g., denied access)

2. **Monitoring and Alerting**:
   - Print a warning after repeated failed logins (e.g., 3 attempts in a row)

---

### Deliverables

- **SecureText-ZeroTrust**: Modified version of SecureText with:
  - Challenge-response authentication
  - Role-based command restrictions
  - Session expiration and sensitive action re-authentication
  - Logging and alerting mechanisms

- **Security Report**:
  - Explain your Zero Trust design choices and limitations
  - Describe how your system verifies identity continuously
  - Compare basic password login, TOTP, and challenge-response

- **Sample Log File**:
  - Show example log output for:
    - Login attempts
    - Authorized and denied actions
    - Session expiration

---

## Extra Info

1. **OAuth Provider Setup**:
   - Choose a provider (GitHub recommended for simplicity)
   - Register your application at https://github.com/settings/applications/new
   - Note your Client ID and Client Secret
   - Set callback URL to `http://localhost:8080/oauth/callback`

## Important Notes

- **API Keys**: Never commit OAuth secrets to your repository - use environment variables
- **Testing**: Test with multiple users and different scenarios
- **Progressive Enhancement**: Each task builds on the previous one(if not conflicting)
- **Security First**: Always consider the security implications of your implementations

## Common Issues and Solutions

### TOTP Issues
- **Time Sync**: Ensure system clock is accurate for TOTP validation
- **QR Code Display**: Use ASCII art for console compatibility
- **Secret Storage**: Encrypt TOTP secrets in the database

### OAuth Issues
- **HTTPS Requirements**: Some providers require HTTPS - use ngrok for local testing
- **State Parameter**: Always validate state to prevent CSRF attacks
- **Token Storage**: Securely store and handle access tokens

### Zero Trust Implementation
- **Logging**: Ensure logs don't contain sensitive information

## Recommended Reading

- RFC 6238 (TOTP specification)
- RFC 6749 (OAuth 2.0 specification)
- NIST SP 800-207 (Zero Trust Architecture)
- OWASP Authentication Cheat Sheet
- Google's BeyondCorp papers on Zero Trust

---

**Due Date**: July 12th, 2026 — 11 PM
**Submission**: Submit your report on Brightspace with your GitHub repository link

**Good Luck!**
