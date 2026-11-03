This project is an interactive, terminal-based database application created in Python to demonstrate robust coding, data security, and operational examining within a clinical healthcare frame.
This project serves as a health-tech simulation showing how sensitive medical data can be protected from unauthorized access at rest and during user authentication.
When a user registers, the system uses a robust `PBKDF2-SHA256` key function running through `hashlib`. Instead of storing cleartext passwords, it pads the input with a 16-byte code to secure random salt via `os.urandom(16)` to defend against attacks.
It also prevents side-channel timing analysis attacks where an opponent concludes correct credentials by measuring minute processing variations down to the millisecond the system handles login verification utilizing constant-time comparison algorithms through `hmac.compare_digest`.
Patient data (Name, Date of Birth, and Clinical Diagnoses/Notes) is captured and processed through a encryption layer using `cryptography.fernet`.
The resulting cipher blocks are attached as binary lines onto a disk storage file (`encrypted_patient_records.enc`). If opened outside the script environment, all medical evaluations appear entirely unreadable, maintaining data privacy.
When an authorized medical staff member logs in, the script manifests a localized cryptographic handle using a protected key file (`secret.key`). 
The runtime system loops through the binary storage blocks, puts in the cipher signature to decrypt the content back into cleartext, and puts the patient database back to the terminal screen.
To satisfy the core security validation requirements, the application creates an append-only chronological logger saved inside `access_audit.log`.
Every state machine transition including user registrations, successful authentications, failed login anomalies, record writes, or file read operations—is put in with a structured timestamp (`%Y-%m-%d %H:%M:%S`) and tied to the active operator's identity.
Python 3.15+
Standard Platform Modules: `hashlib`, `hmac`, `os`, `getpass`, `datetime`
External Cryptographic Packages: `cryptography`
 Make sure your terminal has the required cryptographic library installed: pip install cryptography
 Execute the primary driver application layer:  python main.py
