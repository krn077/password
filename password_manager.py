import os
import json
from crypto_utils import encrypt_password, decrypt_password, derive_key
from getpass import getpass

# Define file storage
FILE_PATH = "passwords.json"

def load_passwords():
    if not os.path.exists(FILE_PATH):
        return {}
    with open(FILE_PATH, 'r') as file:
        return json.load(file)

def save_passwords(passwords):
    with open(FILE_PATH, 'w') as file:
        json.dump(passwords, file)

def add_password(account, password, key):
    passwords = load_passwords()
    passwords[account] = encrypt_password(password, key)
    save_passwords(passwords)
    print(f"Password for {account} added.")

def get_password(account, key):
    passwords = load_passwords()
    if account in passwords:
        decrypted_password = decrypt_password(passwords[account], key)
        print(f"Password for {account}: {decrypted_password}")
    else:
        print(f"No password found for {account}.")

def generate_key(master_password):
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    return key, urlsafe_b64encode(salt).decode()

def retrieve_key(master_password, salt):
    return derive_key(master_password, urlsafe_b64decode(salt.encode()))
