# SecureText ECE 572 Assignment Series

This repository contains a series of assignments for ECE 572 in Summer 2026, taught by Dr. Ardeshir Shojaeinasab. We will be using a console-based messenger application called "SecureText". Students will progressively identify vulnerabilities, demonstrate attacks, and implement security fixes across three assignments.

## What You'll Work On

Over the three assignments you take SecureText from a deliberately broken messenger to one
you'd actually trust, touching:
- Common security vulnerabilities and the attacks that exploit them
- Cryptographic implementations and the ways they go wrong
- Network eavesdropping and traffic analysis
- Authentication and multi-factor authentication
- Zero Trust principles
- Asymmetric cryptography and digital signatures

## Assignment Structure

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
ECE572_SecureText/
├── README.md                  # This file
├── CHANGELOG.md               # What changed each term (v2025, v2026, ...)
├── LICENSE
├── .gitignore
├── assignment1/
│   ├── README.md              # Assignment 1 instructions
│   ├── report_template.md     # Report template
│   ├── requirements.txt       # Pinned Python dependencies for this assignment
│   └── deliverables/          # Your solutions go here
├── assignment2/
│   ├── README.md
│   ├── report_template.md
│   ├── requirements.txt
│   └── deliverables/
├── assignment3/
│   ├── README.md
│   ├── report_template.md
│   ├── requirements.txt
│   └── deliverables/
├── src/
│   └── securetext.py          # Base insecure messenger
├── tools/
│   └── length_extension.py    # Reference length-extension attack (Assignment 1, Task 3)
└── docs/
    └── SETUP.md               # Detailed setup instructions
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

1. **Read the assignment instructions** in the respective `assignmentX/README.md`
2. **Implement your solutions** in the `assignmentX/deliverables/` folder
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
- **Length-extension**: a dependency-free reference attack ships at `tools/length_extension.py`; the `hashpumpy` pip package is a maintained alternative (the older `hash_extender`/`HashPump` tools often won't build on current systems)

### Python Libraries
Each assignment has its own `requirements.txt` listing the packages it needs — install with
`pip install -r assignmentX/requirements.txt`. Assignment 1 runs on the standard library.

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

Read this section as carefully as the tasks. It changed for 2026.

The point of these assignments is the doing. The exam is built around the same attacks
and fixes you implement here, and it asks you to reason as a security expert about
scenarios you haven't seen — identify the threat, the attack, the defense. If you shortcut
the assignment, you don't just risk a plagiarism flag; you walk into the exam having
skipped the practice it tests. The grade you lose there is larger than the one you'd lose
here. That is the whole reason for the rules below.

So the rule for AI tools is about *where* they help, not whether you touch them. Use them
to explain a concept, to debug an error you've already tried to read yourself, to check
your understanding of length extension or HMAC. Do not use them to generate the substance
— the attack scripts, the security fixes, the written analysis. That work has to be yours,
authored and understood, because the exam assumes you did it.

**Disclosure (required).** Every submission must include a `GENAI.md` file in that
assignment's `deliverables/` folder. List the prompts you used in any meaningful way, and
say which files an AI tool touched and how. This is not a trap — honest, specific
disclosure is expected and fine. Heavy undisclosed use that surfaces later is the problem.

**Explainability (required).** Anything you submit, you must be able to explain on request,
in office hours or by email: *why does your forged MAC validate? why does HMAC resist the
attack your other script just pulled off?* If you cannot explain your own submission, we
treat that as an integrity issue, not a knowledge gap. This is exactly how the exam is
graded, so it should not be a surprise.

**Other people's code.** Don't submit someone else's implementation — not a classmate's,
not a past student's, not a copy lifted from a public repo. Talking through ideas and
approaches with classmates is genuinely fine and encouraged; sharing or copying code is
not.

**Reading real code vs. copying it.** This is a security course, and reading real-world
code is part of learning it. Studying how a library computes HMAC, how OpenSSL structures
something, or how a published length-extension tool works — in order to understand it — is
encouraged, and you cite what you read. Copying any of it in as your submitted solution is
not. The test is simple: is the work you hand in authored and understood by you? Cite your
external resources and libraries, and include your private repository link in every
submission.

<!-- ===== OPTIONAL GRADED COMPONENT — delete from this marker to the closing marker to remove it ===== -->
**Optional walkthrough (small bonus).** For a small bonus, give a ~3-minute walkthrough —
recorded or in person — explaining *why your forged MAC validates*: the resumed internal
state, the glue padding, and why knowing `H(k‖m)` is enough to extend it without ever
knowing `k`. It's the clearest signal that the understanding is yours, and it's the kind of
question the written exam will ask. Drop the recording link in your `GENAI.md` or report,
or sign up for a slot.
<!-- ===== end OPTIONAL GRADED COMPONENT ===== -->

## Getting Help

- **Documentation**: Check the `docs/` folder for detailed guides
- **Issues**: Post questions or report bugs or unclear instructions via GitHub Issues

## Important Notes

- Keep your repository private until after the course ends otherwise you receive zero on assignments
- Each assignment builds upon the previous one
- Start early - security implementations can be complex
- Test your solutions thoroughly
- Document your attacks with screenshots and logs

## Course Offerings / History

This is a multi-year course project; its history is part of its value. Each offering is
tagged in git, and `CHANGELOG.md` records what changed between them.

- **Summer 2026 (`v2026`)** — revised offering. See `CHANGELOG.md`.
- **Summer 2025 (`v2025`)** — original offering; first run of the SecureText series.

Future terms: tag the term's final state and add a line here, newest on top.

Good luck!
