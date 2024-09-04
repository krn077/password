import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QLineEdit, QLabel, QMessageBox
from password_manager import add_password, get_password, generate_key, retrieve_key
from getpass import getpass

class PasswordManagerApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle('Password Manager')
        self.setGeometry(100, 100, 400, 300)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout(self.central_widget)

        # Master Password Input
        self.master_password_label = QLabel("Enter your master password:", self)
        self.layout.addWidget(self.master_password_label)

        self.master_password_input = QLineEdit(self)
        self.master_password_input.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(self.master_password_input)

        # Account Name Input
        self.account_name_label = QLabel("Account Name:", self)
        self.layout.addWidget(self.account_name_label)

        self.account_name_input = QLineEdit(self)
        self.layout.addWidget(self.account_name_input)

        # Password Input
        self.password_label = QLabel("Password:", self)
        self.layout.addWidget(self.password_label)

        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(self.password_input)

        # Add Password Button
        self.add_password_button = QPushButton("Add Password", self)
        self.add_password_button.clicked.connect(self.add_password)
        self.layout.addWidget(self.add_password_button)

        # Get Password Button
        self.get_password_button = QPushButton("Get Password", self)
        self.get_password_button.clicked.connect(self.get_password)
        self.layout.addWidget(self.get_password_button)

    def add_password(self):
        master_password = self.master_password_input.text()
        account_name = self.account_name_input.text()
        password = self.password_input.text()

        # Retrieve or generate key
        try:
            key = self.get_key(master_password)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            return

        add_password(account_name, password, key)
        QMessageBox.information(self, "Success", f"Password for {account_name} added.")

    def get_password(self):
        master_password = self.master_password_input.text()
        account_name = self.account_name_input.text()

        # Retrieve or generate key
        try:
            key = self.get_key(master_password)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            return

        try:
            decrypted_password = get_password(account_name, key)
            QMessageBox.information(self, "Password Retrieved", f"Password for {account_name}: {decrypted_password}")
        except KeyError:
            QMessageBox.warning(self, "Not Found", f"No password found for {account_name}.")

    def get_key(self, master_password):
        salt_file = "salt.txt"
        if not os.path.exists(salt_file):
            key, salt = generate_key(master_password)
            with open(salt_file, 'w') as file:
                file.write(salt)
        else:
            with open(salt_file, 'r') as file:
                salt = file.read()
            key = retrieve_key(master_password, salt)
        return key

def main():
    app = QApplication(sys.argv)
    ex = PasswordManagerApp()
    ex.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
