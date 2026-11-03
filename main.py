import os
import hashlib
import hmac
from datetime import datetime
from getpass import getpass

from cryptography.fernet import Fernet

USER_CRED_FILE = "user_auth.txt"
RECORD_FILE = "encrypted_patient_records.enc"
AUDIT_LOG_FILE = "access_audit.log"
KEY_FILE = "secret.key"


def log_audit_event(username, action):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] User: {username} | Action: {action}\n"

    with open(AUDIT_LOG_FILE, "a") as logfile:
        logfile.write(entry)


def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()

    key = Fernet.generate_key()

    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)

    return key


def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        100000
    )

    return password_hash, salt


def register_user():
    print("\n--- New User Registration ---")

    username = input("Choose a username: ").strip()
    password = getpass("Choose a password: ")

    password_hash, salt = hash_password(password)

    with open(USER_CRED_FILE, "w") as cred_file:
        cred_file.write(
            f"{username}:{password_hash.hex()}:{salt.hex()}"
        )

    print("Account created successfully.")
    log_audit_event(username, "ACCOUNT_CREATED")


def authenticate_user():
    print("\n--- Login ---")

    if not os.path.exists(USER_CRED_FILE):
        print("No user found. Please register first.")
        return None

    with open(USER_CRED_FILE, "r") as cred_file:
        stored_data = cred_file.read().strip()

    stored_user, stored_hash_hex, stored_salt_hex = stored_data.split(":")

    username = input("Username: ").strip()
    password = getpass("Password: ")

    salt = bytes.fromhex(stored_salt_hex)
    test_hash, _ = hash_password(password, salt)

    valid_user = username == stored_user
    valid_hash = hmac.compare_digest(
        test_hash.hex(),
        stored_hash_hex
    )

    if valid_user and valid_hash:
        print(f"Welcome, {username}.")
        log_audit_event(username, "SUCCESSFUL_LOGIN")
        return username

    print("Invalid username or password.")
    log_audit_event(
        username if username else "UNKNOWN",
        "FAILED_LOGIN_ATTEMPT"
    )
    return None


def save_patient_record(username, cipher):
    print("\n--- Add Patient Record ---")

    patient_name = input("Patient Name: ").strip()
    patient_dob = input("Date of Birth (MM/DD/YYYY): ").strip()
    condition = input("Medical Notes / Diagnosis: ").strip()

    record = (
        f"Name: {patient_name} | "
        f"DOB: {patient_dob} | "
        f"Condition: {condition} | "
        f"LoggedBy: {username}"
    )

    encrypted_record = cipher.encrypt(record.encode())

    with open(RECORD_FILE, "ab") as record_file:
        record_file.write(encrypted_record + b"\n")

    print("Record saved.")

    log_audit_event(
        username,
        f"ADDED_RECORD_FOR_{patient_name.replace(' ', '_')}"
    )


def view_patient_records(username, cipher):
    print("\n--- Patient Records ---")

    if not os.path.exists(RECORD_FILE):
        print("No records found.")
        return

    try:
        with open(RECORD_FILE, "rb") as record_file:
            records = record_file.readlines()

        for index, encrypted_record in enumerate(records, start=1):
            decrypted_record = cipher.decrypt(
                encrypted_record.strip()
            )

            print(
                f"Record #{index}: "
                f"{decrypted_record.decode('utf-8')}"
            )

        log_audit_event(username, "VIEWED_PATIENT_RECORDS")

    except Exception as error:
        print(f"Error reading records: {error}")
if __name__ == "__main__":
    print("--- Starting Patient Record System ---")
    
    # 1. Initialize the encryption key engine
    secret_key = load_or_create_key()
    fernet_cipher = Fernet(secret_key)
    
    current_user = None

    # 2. Main Application Loop
    while True:
        if not current_user:
            print("\n1. Register New Account")
            print("2. Login")
            print("3. Exit")
            choice = input("Select an option: ").strip()

            if choice == "1":
                register_user()
            elif choice == "2":
                current_user = authenticate_user()
            elif choice == "3":
                print("Exiting system. Goodbye.")
                break
            else:
                print("Invalid choice. Try again.")
        else:
            print(f"\n--- Logged in as: {current_user} ---")
            print("1. Add Patient Record")
            print("2. View Patient Records")
            print("3. Logout")
            choice = input("Select an option: ").strip()

            if choice == "1":
                save_patient_record(current_user, fernet_cipher)
            elif choice == "2":
                view_patient_records(current_user, fernet_cipher)
            elif choice == "3":
                print(f"Logging out {current_user}...")
                current_user = None
            else:
                print("Invalid choice. Try again.")
    print("--- Starting Patient Record System ---")