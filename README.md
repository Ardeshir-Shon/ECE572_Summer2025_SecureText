# SecureText ECE 572 Assignment Series

This repository contains series of assignments for the ECE 572 in Summer 2025, by Dr. Ardeshir Shojaeinasab. We will be using a console-based messenger application called "SecureText". Students will progressively identify vulnerabilities, demonstrate attacks, and implement security fixes across three assignments.

## Learning Objectives

By completing this assignment series, you will gain hands-on experience with:
- Common security vulnerabilities and attack techniques
- Cryptographic implementations and their pitfalls
- Network security and traffic analysis
- Authentication mechanisms and multi-factor authentication
- Zero Trust security principles
- Asymmetric cryptography and digital signatures

## Assinment Structure

This hands-on practice is divided into **three assignments**, each building upon the previous one:

### Assignment 1: Foundations of Security Vulnerabilities
**Focus**: Basic security concepts, password security, and network attacks
- **Task 1**: Vulnerability Analysis (analyze the provided insecure messenger)
- **Task 2**: Password Security (hashing, salting)
- **Task 3**: Network Security (eavesdropping, message tampering, MAC attacks)

### Assignment 2: Advanced Authentication and Authorization
**Focus**: Modern authentication mechanisms and access control
- **Task 4**: Multi-Factor Authentication (TOTP implementation)
- **Task 5**: OAuth Integration (third-party authentication)
- **Task 6**: Zero Trust Implementation (identity verification, least privilege)

### Assignment 3: Advanced Cryptography and Secure Communication
**Focus**: End-to-end security and cryptographic protocols
- **Task 7**: Asymmetric Cryptography (RSA/ECDSA key exchange)
- **Task 8**: Digital Signatures (message authentication and non-repudiation)
- **Task 9**: Secure Protocol Design (putting it all together)

## Getting Started

### Prerequisites
- Python 3.7 or higher
- Basic understanding of networking concepts
- Solid knowledge of cryptography and security scenarios explained in the class, ECE 572
- Familiarity with command-line tools
- Git installed on your system

### Initial Setup

A word on why we do not use GitHub's Fork button: a fork of a public repository is
itself always public, and GitHub will not let you make it private. Since your graded
work must stay private until the course ends, forking would force you to choose between
the rules and the tooling. Instead, mirror the course repo into a new **private** repo
of your own. It takes four commands and you only do it once.

1. On GitHub, create a **new, empty, private** repository (no README, no `.gitignore`,
   no license). Name it whatever you like, e.g. `ECE572_SecureText_yourname`.

2. Mirror the course repo into your private repo:
   ```bash
   git clone --bare https://github.com/Ardeshir-Shon/ECE572_SecureText.git
   cd ECE572_SecureText.git
   git push --mirror https://github.com/YOUR_USERNAME/YOUR_PRIVATE_REPO.git
   cd ..
   rm -rf ECE572_SecureText.git
   ```
   (If that course-repo URL 404s, use the exact URL posted on Brightspace — the
   repository name may differ between terms.)

3. Clone your private repo and create a working branch:
   ```bash
   git clone https://github.com/YOUR_USERNAME/YOUR_PRIVATE_REPO.git
   cd YOUR_PRIVATE_REPO
   git checkout -b assignment1-solutions   # X in assignmentX-solutions is the assignment number
   ```

4. Add the course repo as `upstream` so you can pull fixes and updates during the term:
   ```bash
   git remote add upstream https://github.com/Ardeshir-Shon/ECE572_SecureText.git
   git remote -v
   ```

### Repository Structure

```
ECE572_Summer2025_SecureText/
├── README.md                     # This file
├── assignments/
│   ├── assignment1/
│   │   ├── README.md            # Assignment 1 instructions
│   │   ├── REPORT_TEMPLATE.md   # Report template
│   │   └── deliverables/        # Your solutions go here
│   ├── assignment2/
│   │   ├── README.md            # Assignment 2 instructions
│   │   ├── REPORT_TEMPLATE.md   # Report template
│   │   └── deliverables/        # Your solutions go here
│   └── assignment3/
│       ├── README.md            # Assignment 3 instructions
│       ├── REPORT_TEMPLATE.md   # Report template
│       └── deliverables/        # Your solutions go here
├── src/
│   └── securetext.py           # Base insecure messenger
│ 
├── docs/
│   └── SETUP.md               # Detailed setup instructions
│
└── .gitignore
```

## Base Application

The repository includes a fully functional but **intentionally insecure** messenger application (`src/securetext.py`) that serves as the foundation for all assignments. This application includes:

- Account creation and authentication
- Real-time messaging via TCP sockets
- User management and online status
- JSON-based client-server protocol

### Running the Base Application

1. **Start the server**:
   ```bash
   python3 src/securetext.py server
   ```

2. **Start a client** (run multiple times for different users):
   ```bash
   python3 src/securetext.py
   ```

3. **Create accounts** and start messaging to explore the application

## Security Warnings

**IMPORTANT**: The base application contains multiple intentional security and privacy vulnerabilities. These vulnerabilities are **by design** and will be addressed throughout the assignments.

## Assignment Workflow

For each assignment:

1. **Read the assignment instructions** in the respective `assignments/assignmentX/README.md`
2. **Implement your solutions** in the `assignments/assignmentX/deliverables/` folder
3. **Write your report** using the provided template and put it as a deliverable beside the codes
4. **Commit your changes**:
   ```bash
   git add .
   git commit -m "Complete Assignment X Task Y"
   git push origin assignmentX-solutions
   ```
5. **Submit on Brightspace** with the link to your private GitHub repository, and re-upload the report itself to Brightspace

## Tools You Might Need

### Network Analysis Tools
- **Wireshark** (GUI packet analyzer)
- **tcpdump** (command-line packet capture)
- **netstat** (network connection monitoring)

### Cryptographic Tools
- **hashcat** (password cracking)
- **OpenSSL** (cryptographic operations)
- **hash_extender** or **HashPump** (length extension attacks)

### Python Libraries
You may need to install additional Python packages.

## Documentation

Detailed extra setup documentation is available in the `docs/` folder, if needed:
- **Setup Guide**: Complete environment setup instructions

## Assessment Criteria

Each assignment will be evaluated on:
- **Technical Implementation** (40%): Correctness and completeness of solutions
- **Security Understanding** (30%): Depth of vulnerability analysis and countermeasures
- **Attack Demonstrations** (20%): Clear evidence of successful attacks
- **Overall Report Quality** (10%): Clarity, organization, and proper screenshot evidences

## Academic Integrity

- All work must be your own individual effort
- You may discuss concepts with classmates but not share code
- Use **GenAI** for help but do not let **GenAI** to do all the work and you should understand everything yourself
- If you used any **GenAI** help make sure you cite the contribution of **GenAI** properly
- Properly cite any external resources or libraries used
- Include your private repository link in all submissions

## Getting Help

- **Documentation**: Check the `docs/` folder for detailed guides
- **Issues**: Post questions or report bugs or unclear instructions via GitHub Issues

## Important Notes

- Keep your repository private until after the course ends otherwise you receive zero on assignments
- Each assignment builds upon the previous one
- Start early - security implementations can be complex
- Test your solutions thoroughly
- Document your attacks with screenshots and logs

## Learning Outcomes

By the end of this lab series, you will have:
- Built a secure messaging application from an insecure foundation
- Demonstrated real-world attack techniques
- Implemented modern authentication and cryptographic protocols
- Gained practical experience with security tools and methodologies
- Developed a security-first mindset for software development

Good luck!
