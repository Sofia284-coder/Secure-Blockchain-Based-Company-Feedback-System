import hashlib
import json
import time
from dataclasses import dataclass, asdict
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad

    HAS_AES = True
except Exception:
    HAS_AES = False
#utility functions
def sha256_hex(data_bytes: bytes) -> str:
 return hashlib.sha256(data_bytes).hexdigest()


def mask_employee_id(emp_id: str) -> str:
    if len(emp_id) <= 4:
        return "****"

    return emp_id[:2] + "*" * (len(emp_id) - 4) + emp_id[-2:]


def derive_key_from_password(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()

#Encryption functions
def aes_encrypt(plaintext: str, key_bytes: bytes) -> bytes:
    key = key_bytes[:16]
    iv = hashlib.sha256(key_bytes + str(time.time()).encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return iv + ct

def aes_decrypt(iv_and_ct: bytes, key_bytes: bytes) -> str:
    key = key_bytes[:16]
    iv = iv_and_ct[:16]
    ct = iv_and_ct[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()


def vigenere_encrypt(plaintext: str, key: str) -> str:
    res = []
    key = key.upper()
    klen = len(key)
    j = 0
    for ch in plaintext:
        if ch.isalpha():
            base = 'A' if ch.isupper() else 'a'
            p = ord(ch) - ord(base)
            k = ord(key[j % klen]) - ord('A')
            c = (p + k) % 26
            res.append(chr(c + ord(base)))
            j += 1
        else:
            res.append(ch)
    return ''.join(res)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    res = []
    key = key.upper()
    klen = len(key)
    j = 0
    for ch in ciphertext:
        if ch.isalpha():
            base = 'A' if ch.isupper() else 'a'
            c = ord(ch) - ord(base)
            k = ord(key[j % klen]) - ord('A')
            p = (c - k) % 26
            res.append(chr(p + ord(base)))
            j += 1
        else:
            res.append(ch)

    return ''.join(res)


#BLOCKCHAIN CLASSES

@dataclass
class Block:
    index: int
    timestamp: float
    employee_mask: str
    encrypted_vote_hex: str
    vote_hash: str
    previous_hash: str
    nonce: int = 0
    hash: str = ""

    def compute_hash(self) -> str:
        block_string = f"{self.index}{self.timestamp}{self.employee_mask}{self.encrypted_vote_hex}{self.vote_hash}{self.previous_hash}{self.nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine(self, difficulty: int = 2):
        prefix = '0' * difficulty
        self.nonce = 0
        while True:
            self.hash = self.compute_hash()
            if self.hash.startswith(prefix):
                return
            self.nonce += 1

class Blockchain:
    def __init__(self, difficulty: int = 2):
        self.chain = []
        self.difficulty = difficulty
        genesis = Block(
            index=0,
            timestamp=time.time(),
            employee_mask="GENESIS",
            encrypted_vote_hex="",
            vote_hash="",
            previous_hash="0",
            nonce=0,
            hash=""
        )
        genesis.hash = genesis.compute_hash()
        self.chain.append(genesis)

    def add_block(self, employee_mask: str, encrypted_vote_hex: str, vote_hash: str):
        last = self.chain[-1]
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            employee_mask=employee_mask,
            encrypted_vote_hex=encrypted_vote_hex,
            vote_hash=vote_hash,
            previous_hash=last.hash
        )

        new_block.mine(self.difficulty)
        self.chain.append(new_block)

        return new_block

    def is_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            cur = self.chain[i]
            prev = self.chain[i - 1]
            if cur.previous_hash != prev.hash:
                print(f"  Previous hash mismatch at block {i}")
                print(f"   Expected: {prev.hash}")
                print(f"   Got: {cur.previous_hash}")
                return False

            if cur.compute_hash() != cur.hash:
                print(f"  Hash mismatch at block {i}")
                print(f"   Stored hash: {cur.hash}")
                print(f"   Computed hash: {cur.compute_hash()}")
                return False

        return True

    def display_chain(self):
        print("BLOCKCHAIN LEDGER")
        for block in self.chain:
            if block.index == 0:
                print(f"Block #{block.index} [GENESIS]")
            else:
                print(f"\nBlock #{block.index}")
                print(f"  Employee: {block.employee_mask}")
                print(f"  Vote Hash: {block.vote_hash[:16]}...")
                print(f"  Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(block.timestamp))}")
                print(f"  Prev Hash: {block.previous_hash[:16]}...")
                print(f"  This Hash: {block.hash[:16]}...")
                print(f"  Nonce: {block.nonce}")

        print("=" * 60 + "\n")


# COMPANY FEEDBACK SYSTEM

class CompanyFeedbackSystem:

    def __init__(self, use_aes=True, difficulty=2):
        # Structure: { emp_id: {'password_hash': ..., 'department': ..., 'has_voted': bool} }
        self.employees_db = {}

        self.blockchain = Blockchain(difficulty=difficulty)
        self.use_aes = use_aes and HAS_AES
        self.current_proposal = ""
        if use_aes and not HAS_AES:
            print("PyCryptodome not available. Using Vigenere cipher fallback.")
            self.use_aes = False

    def set_proposal(self, proposal_text: str):

        self.current_proposal = proposal_text
        print(f"\nCurrent Proposal: {proposal_text}\n")

    def register_employee(self, emp_id: str, password: str, department: str = "General"):
        if emp_id in self.employees_db:
            raise ValueError(f" Employee {emp_id} already registered")
        pwd_hash = sha256_hex(password.encode())

        self.employees_db[emp_id] = {
            'password_hash': pwd_hash,
            'department': department,
            'has_voted': False
        }

        print(f" Registered: {emp_id} ({department})")
        return True

    def authenticate(self, emp_id: str, password: str) -> bool:
        rec = self.employees_db.get(emp_id)
        if not rec:
            return False  # Employee not found
        # Hashing the entered password and comparing with stored hash
        return rec['password_hash'] == sha256_hex(password.encode())

    def cast_vote(self, emp_id: str, password: str, vote: str, vigenere_key: str = "TECHCORP"):
        if vote not in ["Yes", "No", "Abstain"]:
            raise ValueError("Vote must be 'Yes', 'No', or 'Abstain'")

        # Verify this is really the employee and password is correct
        if not self.authenticate(emp_id, password):
            raise PermissionError(" Authentication failed")
        if self.employees_db[emp_id]['has_voted']:
            raise PermissionError(f" Employee {emp_id} has already voted")
        print(f" Encrypting vote for {emp_id}...")

        if self.use_aes:
            key_bytes = derive_key_from_password(password)
            ciphertext_bytes = aes_encrypt(vote, key_bytes)
            encrypted_hex = ciphertext_bytes.hex()

        else:
            encrypted_text = vigenere_encrypt(vote, vigenere_key)
            encrypted_hex = encrypted_text.encode().hex()
        vote_hash = sha256_hex(bytes.fromhex(encrypted_hex))
        employee_mask = mask_employee_id(emp_id)

        print(f" Mining block...")
        block = self.blockchain.add_block(employee_mask, encrypted_hex, vote_hash)

        self.employees_db[emp_id]['has_voted'] = True

        print(f" Vote recorded in Block #{block.index}")
        print(f"  Hash: {block.hash[:16]}...")
        return block

    def tally_votes(self, password_lookup: dict = None, vigenere_key: str = "TECHCORP"):

        print("VOTE TALLYING IN PROGRESS")

        print("\n Verifying blockchain integrity...")
        if not self.blockchain.is_valid():
            raise RuntimeError("BLOCKCHAIN INVALID - Tallying aborted!")
        print("Blockchain verified")

        counts = {"Yes": 0, "No": 0, "Abstain": 0}
        tampered_count = 0
        total_votes = 0
        for block in self.blockchain.chain[1:]:
            enc_hex = block.encrypted_vote_hex
            recomputed_hash = sha256_hex(bytes.fromhex(enc_hex))

            if recomputed_hash != block.vote_hash:
                print(f"Block {block.index}: TAMPERED - Skipping")
                tampered_count += 1
                continue
            decrypted = None

            if self.use_aes:

                if not password_lookup:
                    raise ValueError("Password lookup required for AES decryption")

                for emp_id, pwd in password_lookup.items():
                    try:
                        keyb = derive_key_from_password(pwd)
                        dec = aes_decrypt(bytes.fromhex(enc_hex), keyb)
                        decrypted = dec
                        break
                    except Exception:
                        continue

                if decrypted is None:
                    decrypted = "<undecryptable>"

            else:
                decrypted = vigenere_decrypt(bytes.fromhex(enc_hex).decode(), vigenere_key)

            if decrypted in counts:
                counts[decrypted] += 1
                total_votes += 1
            else:
                print(f" Block {block.index}: Invalid vote '{decrypted}' - Skipping")

        if total_votes > 0:
            yes_pct = (counts["Yes"] / total_votes) * 100
            no_pct = (counts["No"] / total_votes) * 100
            abstain_pct = (counts["Abstain"] / total_votes) * 100
        else:
            yes_pct = no_pct = abstain_pct = 0

        print("FINAL RESULTS")
        print(f"\nProposal: {self.current_proposal}")
        print(f"\nTotal Employees: {len(self.employees_db)}")
        print(f"Votes Cast: {total_votes} ({(total_votes / len(self.employees_db) * 100):.1f}% participation)")

        print(f"\n{'Results:':<20}")
        print(f"  YES:     {counts['Yes']:<3} ({yes_pct:.1f}%)")
        print(f"  NO:      {counts['No']:<3} ({no_pct:.1f}%)")
        print(f"  BSTAIN: {counts['Abstain']:<3} ({abstain_pct:.1f}%)")

        if counts["Yes"] > counts["No"]:
            decision = "APPROVED"
        elif counts["No"] > counts["Yes"]:
            decision = " REJECTED"
        else:
            decision = "  TIE - Further Review Needed"

        print(f"\nDecision: {decision}")

        print(f"\nBlockchain Status:")
        print(f"  Total Blocks: {len(self.blockchain.chain)} (1 genesis + {total_votes} votes)")
        print(f"  Tampered Votes Detected: {tampered_count}")
        print(f"  Chain Integrity: {'✓ VERIFIED' if self.blockchain.is_valid() else 'CORRUPTED'}")

        return {
            "proposal": self.current_proposal,
            "total_employees": len(self.employees_db),
            "votes_cast": total_votes,
            "results": counts,
            "percentages": {
                "Yes": yes_pct,
                "No": no_pct,
                "Abstain": abstain_pct
            },
            "decision": decision,
            "tampered_votes": tampered_count
        }

    def get_participation_stats(self):

        # Count employees who voted
        voted = sum(1 for emp in self.employees_db.values() if emp['has_voted'])
        not_voted = len(self.employees_db) - voted

        print("PARTICIPATION STATISTICS")
        print(f"Total Employees: {len(self.employees_db)}")
        print(f"Voted: {voted} ({voted / len(self.employees_db) * 100:.1f}%)")
        print(f"Not Voted: {not_voted} ({not_voted / len(self.employees_db) * 100:.1f}%)")


def demo():
    print("TECHCORP COMPANY FEEDBACK SYSTEM".center(60))

    system = CompanyFeedbackSystem(use_aes=True, difficulty=2)

    system.set_proposal("Implement 4-Day Work Week (4x10 hour days)")

    print("\n EMPLOYEE REGISTRATION")
    system.register_employee("EMP001", "alice_secure_pass", "Engineering")
    system.register_employee("EMP002", "bob_secure_pass", "Marketing")
    system.register_employee("EMP003", "carol_secure_pass", "HR")
    system.register_employee("EMP004", "dave_secure_pass", "Sales")
    system.register_employee("EMP005", "eve_secure_pass", "Engineering")

    print("VOTING PHASE")

    print("Alice (Engineering) votes...")
    system.cast_vote("EMP001", "alice_secure_pass", "Yes")

    print("\n Bob (Marketing) votes...")
    system.cast_vote("EMP002", "bob_secure_pass", "No")

    print("\n Carol (HR) votes...")
    system.cast_vote("EMP003", "carol_secure_pass", "Yes")

    print("\n Dave (Sales) votes...")
    system.cast_vote("EMP004", "dave_secure_pass", "Abstain")

    print("\n Eve (Engineering) votes...")
    system.cast_vote("EMP005", "eve_secure_pass", "Yes")

    print(" Testing double-vote prevention...")
    try:
        system.cast_vote("EMP001", "alice_secure_pass", "No")
    except PermissionError as e:
        print(f" Double vote blocked: {e}")

    system.get_participation_stats()

    system.blockchain.display_chain()

    passwords = {
        "EMP001": "alice_secure_pass",
        "EMP002": "bob_secure_pass",
        "EMP003": "carol_secure_pass",
        "EMP004": "dave_secure_pass",
        "EMP005": "eve_secure_pass"
    }

    results = system.tally_votes(password_lookup=passwords)


if __name__ == "__main__":

    demo()
