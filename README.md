# 🗳️ Secure Blockchain-Based Company Feedback System

A Python-based secure voting and feedback system for organizations that combines **blockchain technology**, **cryptographic encryption**, and **employee authentication** to ensure transparent, tamper-proof voting.

---

## 🚀 Features

- 🔐 Employee authentication using SHA-256 password hashing
- 🧾 Vote encryption using:
  - AES (PyCryptodome) OR
  - Vigenère cipher fallback (if AES unavailable)
- ⛓️ Blockchain-based vote storage
- ⛏️ Proof-of-Work mining for vote integrity
- 🛡️ Tamper detection via hash verification
- 👤 Employee ID masking for privacy
- 📊 Automated vote tallying system
- 📈 Participation statistics reporting

---

## 🏗️ System Architecture

### 1. Authentication Layer
- SHA-256 hashed passwords
- Employee registration and login validation

### 2. Encryption Layer
- AES encryption (secure mode)
- Vigenère cipher fallback (educational mode)

### 3. Blockchain Layer
- Each vote stored as a block
- SHA-256 hashing for integrity
- Proof-of-Work mining (difficulty adjustable)

### 4. Tallying Engine
- Verifies blockchain integrity
- Detects tampering
- Decrypts and counts votes
- Produces final decision

---

## 📦 Installation

```bash
pip install pycryptodome
````

(If not installed, system automatically falls back to Vigenère cipher.)

---

## ▶️ Usage

Run the demo:

```bash
python main.py
```

---

## 🧪 Demo Workflow

* Register employees
* Set company proposal
* Employees cast encrypted votes
* Votes are mined into blockchain blocks
* System verifies integrity
* Votes are decrypted and tallied
* Final decision is generated

---

## 🔐 Security Highlights

* One employee = one vote enforcement
* Blockchain immutability
* Hash-based tamper detection
* Password-based AES key derivation
* Masked employee identity in ledger

---

## 📊 Example Output

* Vote distribution (Yes / No / Abstain)
* Participation percentage
* Blockchain validity status
* Tamper detection results
* Final decision (Approved / Rejected / Tie)

---

## 📚 Concepts Used

* Blockchain fundamentals
* SHA-256 hashing
* Symmetric encryption (AES)
* Classical cryptography (Vigenère cipher)
* Proof-of-Work mining
* Data integrity verification

---

## 👨‍💻 Author

Developed as a secure voting simulation project demonstrating blockchain and cryptographic principles in Python.
