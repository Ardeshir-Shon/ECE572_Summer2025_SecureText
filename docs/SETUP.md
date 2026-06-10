# Development Environment Setup Guide

This guide will help you set up your development environment for the ECE 572 Summer 2025 assignment series

## Prerequisites

### System Requirements
- **Operating System**: Linux, macOS, or Windows with WSL2
- **Python**: Version 3.7 or higher
- **Git**: For version control and repository management
- **Terminal/Command Line**: Basic familiarity required

## Python Environment Setup

### 1. Verify Python Installation
```bash
python3 --version
# Should output Python 3.7.x or higher
```

### 2. [MANDATORY]Create Virtual Environment (It helps us run everything as you run)

### 3. Install Required Python Libraries

## Network Analysis Tools

### Wireshark (GUI)

#### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install wireshark
sudo usermod -a -G wireshark $USER
# Log out and back in for group membership to take effect

### tcpdump (Command Line)

#### Linux
```bash
sudo apt install tcpdump
```

### OpenSSL
```bash
# Verify installation (usually pre-installed)
openssl version

# If not installed:
# Ubuntu/Debian
sudo apt install openssl

```

## Repository Setup

### 1. Mirror the Course Repo into a Private Repo

Do **not** use GitHub's Fork button. A fork of a public repo is always public and cannot
be made private, which conflicts with the rule that your graded work stays private until
the course ends. Mirror the repo into your own private repo instead:

1. On GitHub, create a new, **empty, private** repository (no README/license).
2. Mirror the course repo into it:
   ```bash
   git clone --bare https://github.com/Ardeshir-Shon/ECE572_SecureText.git
   cd ECE572_SecureText.git
   git push --mirror https://github.com/YOUR_USERNAME/YOUR_PRIVATE_REPO.git
   cd ..
   rm -rf ECE572_SecureText.git
   ```
   (If that URL 404s, use the exact course-repo URL posted on Brightspace.)
3. Clone your private repo to work in:
   ```bash
   git clone https://github.com/YOUR_USERNAME/YOUR_PRIVATE_REPO.git
   cd YOUR_PRIVATE_REPO
   ```

### 2. Set Up Remote Tracking
```bash
# Add the course repo as 'upstream' so you can fetch/pull fixes and updates during the term
git remote add upstream https://github.com/Ardeshir-Shon/ECE572_SecureText.git

# Verify remotes
git remote -v
```

### 3. Create Working Branches
```bash
# For Assignment 1
git checkout -b assignment1- (or any other name you like)

# For Assignment 2  
git checkout -b assignment2-solutions (or any other name you like)

# For Assignment 3
git checkout -b assignment3-solutions (or any other name you like)
```

## Testing Your Setup

### 1. Test Base Application
```bash
cd src/
python3 securetext.py server
python3 securetext.py
```

### 2. Test Network Capture
```bash
# In one terminal
sudo tcpdump -i lo -A -s 0 port 12345

# In another terminal, run SecureText and send messages
# You should see plaintext traffic in tcpdump output
```

## Troubleshooting

### Common Issues

#### Permission Denied (Network Capture)
```bash
# Add user to wireshark group
sudo usermod -a -G wireshark $USER
# Log out and back in

# For tcpdump, use sudo
sudo tcpdump -i lo port 12345
```

#### Port Already in Use
```bash
# Find process using port 12345
netstat -tulpn | grep 12345
# Or
lsof -i :12345

# Kill the process to free up the port
kill -9 PID_NUMBER
```

## Performance Optimization

### Python Optimization
```bash
# Use faster JSON library
pip install orjson

# Use faster cryptographic operations
pip install pycryptodome  # Instead of pycrypto
```


If you encounter any issues not covered in this guide, please:
1. Check the course conversations for similar issues
2. Consult the official documentation for the specific tool
3. Create a GitHub issue in your repository describing the problem
4. Search or consult with GenAI to troubleshoot the errors

Good luck!
