from getpass import getpass
from password_manager import add_password, get_password, generate_key, retrieve_key
import os

SALT_FILE = "salt.txt"

def main():
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, 'r') as file:
            salt = file.read()
        master_password = getpass("Enter your master password: ")
        key = retrieve_key(master_password, salt)
    else:
        master_password = getpass("Set a new master password: ")
        key, salt = generate_key(master_password)
        with open(SALT_FILE, 'w') as file:
            file.write(salt)

    while True:
        choice = input("Choose an option: [add/get/exit]: ").strip().lower()
        if choice == 'add':
            account = input("Enter account name: ")
            password = getpass("Enter password: ")
            add_password(account, password, key)
        elif choice == 'get':
            account = input("Enter account name: ")
            get_password(account, key)
        elif choice == 'exit':
            break
        else:
            print("Invalid option. Please choose again.")

if __name__ == "__main__":
    main()
