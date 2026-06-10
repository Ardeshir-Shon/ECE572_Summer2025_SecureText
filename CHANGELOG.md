# Changelog

Notable changes to the SecureText assignment series, organized by course offering. Each
entry corresponds to a git tag (`v2025`, `v2026`, ...). Newest term on top; future terms
append a new tagged section above the previous one and tag the term's final approved state.

## [v2026] — Summer 2026

Revision of the original offering. No change to the rubric weightings, the core
identify → attack → fix pedagogy, or the base app's intentional vulnerabilities — those
were correct as they were.

### Fixed
- **Private-repo workflow.** GitHub forks of a public repo are always public and can't be
  made private, which contradicted the "keep it private" rule. Replaced every "click Fork"
  instruction (root README, `docs/SETUP.md`) with a create-private-repo + `push --mirror` +
  `upstream` workflow.
- **Repo-structure docs.** The structure diagrams showed assignments under a nonexistent
  `assignments/` wrapper; the real layout is `assignment1/2/3` at the repo root. Redrew the
  diagrams and fixed the deliverables paths.
- **Template filename casing.** Docs referenced `REPORT_TEMPLATE.md` but the file is
  `report_template.md`; standardized to the on-disk name (breaks on case-sensitive systems).
- **Year and due dates.** Updated all Summer 2025 references to 2026 and refreshed the
  assignment due dates.
- **Assignment 1 cross-reference.** The Secure MAC deliverable was mislabeled Task 3 Part C;
  it is Part D.

### Coherence fixes (cross-file review)
- **F1 — Hash standardization.** Changed Assignment 1's flawed MAC from `MD5(k‖m)` to
  `SHA-256(k‖m)` everywhere it appears (README Part B/C and the deliverables table) so the
  assignment matches the course notes' length-extension example, and switched
  `tools/length_extension.py` to SHA-256. Verified end to end.
- **F2 — Assignment 3 description.** The root README advertised A3 as asymmetric
  crypto / digital signatures / non-repudiation; the real A3 is end-to-end encryption
  (ECDH P-256 + AES-256-GCM + HKDF + 30-min sessions). Rewrote the root README A3 block to
  match; `assignment3/README.md` was already correct and is unchanged.
- **F3 — Assignment 2 point total (pending instructor confirmation).** A2 summed to 115;
  changed Task 4 from 40 to 25 so it totals 100, matching A1's `/100` scheme. Confirm or
  revert.
- **F4 — OAuth callback URL.** A2 gave two redirect URIs; standardized both to
  `http://localhost:8080/oauth/callback`.

### Added
- **Pinned `requirements.txt`** in each assignment (A1: stdlib-only core with optional pins;
  A2: pyotp, qrcode, requests; A3: cryptography).
- **`tools/length_extension.py`** — a dependency-free, commented reference length-extension
  attack against `SHA-256(k‖m)`, so students don't lose a day to `hash_extender` (needs
  compiling) or `HashPump` (stale). The maintained `hashpumpy` package is documented as an
  alternative.
- **Explicit Assignment 1 deliverable filenames** so grading is consistent.
- **AI / originality policy.** Rewrote the Academic Integrity section: required `GENAI.md`
  disclosure, a required explainability clause tied to the exam framing, a clear
  read-to-learn vs. copy-as-submission line, and an optional, easy-to-remove graded
  3-minute walkthrough component.
- **`users.json` gotcha note** (written relative to the working directory) plus a
  `recv(1024)` truncation note for Assignment 1 Task 3.
- **This CHANGELOG and a course-offerings note** in the README.

### Changed
- Editorial pass on the READMEs for a direct, instructor voice (no task-content changes).
- `users.json` is now gitignored.

## [v2025] — Summer 2025 (baseline)

First offering of the SecureText assignment series in ECE 572.

- Intentionally insecure console messenger base app (`src/securetext.py`): plaintext
  password storage, unauthenticated password reset, plaintext network protocol.
- **Assignment 1** — vulnerability analysis, password hashing/salting, network
  eavesdropping, and the `H(k‖m)` MAC plus length-extension attack and HMAC fix.
- **Assignment 2** — TOTP multi-factor auth, GitHub OAuth, and Zero Trust (challenge-
  response, RBAC, session security, logging).
- **Assignment 3** — end-to-end encryption with ECDH (P-256) + AES-256-GCM and session
  management.
- Per-assignment report templates and a setup guide.
