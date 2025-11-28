import tkinter as tk
from tkinter import messagebox, ttk
from cryptography.fernet import Fernet, InvalidToken
import os
import pyperclip

class SecureMessagingTool:
    def __init__(self):
        self.key_file = "encryption_key.txt"
        if not os.path.exists(self.key_file):
            self.key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(self.key)
        else:
            with open(self.key_file, "rb") as f:
                self.key = f.read()
        self.cipher_suite = Fernet(self.key)

    def encrypt_message(self, message):
        encrypted_message = self.cipher_suite.encrypt(message.encode())
        return encrypted_message.decode()

    def decrypt_message(self, encrypted_message):
        try:
            decrypted_message = self.cipher_suite.decrypt(encrypted_message.encode())
            return decrypted_message.decode()
        except InvalidToken:
            raise ValueError("Invalid encrypted message")

class EncryptionWindow:
    def __init__(self, parent, secure_messaging_tool):
        self.parent = parent
        self.secure_messaging_tool = secure_messaging_tool

        self.message_label = tk.Label(parent, text="Enter Your Message:", font=("Arial", 16))
        self.message_label.pack(pady=10)

        self.message_entry = tk.Entry(parent, font=("Arial", 16), width=50)
        self.message_entry.pack(pady=10)

        self.encrypt_button = tk.Button(parent, text="Encrypt", font=("Arial", 16), command=self.encrypt_message)
        self.encrypt_button.pack(pady=10)

        self.encrypted_message_label = tk.Label(parent, text="There is Your Message Code:", font=("Arial", 16))
        self.encrypted_message_label.pack(pady=10)

        self.encrypted_message_entry = tk.Entry(parent, font=("Arial", 16), width=50)
        self.encrypted_message_entry.pack(pady=10)

        self.copy_button = tk.Button(parent, text="Copy Code", font=("Arial", 16), command=self.copy_code)
        self.copy_button.pack(pady=10)

    def encrypt_message(self):
        message = self.message_entry.get()
        encrypted_message = self.secure_messaging_tool.encrypt_message(message)
        self.encrypted_message_entry.delete(0, tk.END)
        self.encrypted_message_entry.insert(0, encrypted_message)

    def copy_code(self):
        encrypted_message = self.encrypted_message_entry.get()
        pyperclip.copy(encrypted_message)
        messagebox.showinfo("Success", "Code copied to clipboard!")

class DecryptionWindow:
    def __init__(self, parent, secure_messaging_tool):
        self.parent = parent
        self.secure_messaging_tool = secure_messaging_tool

        self.encrypted_message_label = tk.Label(parent, text="Enter Your Code Message:", font=("Arial", 16))
        self.encrypted_message_label.pack(pady=10)

        self.encrypted_message_entry = tk.Entry(parent, font=("Arial", 16), width=50)
        self.encrypted_message_entry.pack(pady=10)

        self.decrypt_button = tk.Button(parent, text="Decrypt", font=("Arial", 16), command=self.decrypt_message)
        self.decrypt_button.pack(pady=10)

        self.decrypted_message_label = tk.Label(parent, text="This is the Message:", font=("Arial", 16))
        self.decrypted_message_label.pack(pady=10)

        self.decrypted_message_entry = tk.Entry(parent, font=("Arial", 16), width=50)
        self.decrypted_message_entry.pack(pady=10)

    def decrypt_message(self):
        encrypted_message = self.encrypted_message_entry.get()
        try:
            decrypted_message = self.secure_messaging_tool.decrypt_message(encrypted_message)
            self.decrypted_message_entry.delete(0, tk.END)
            self.decrypted_message_entry.insert(0, decrypted_message)
        except ValueError as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    secure_messaging_tool = SecureMessagingTool()
    root = tk.Tk()
    root.title("Secure Messaging Tool")
    root.geometry("800x600")
    root.configure(bg="#F0F0F0")

    # Create tabs
    tab_control = ttk.Notebook(root)
    tab_control.pack(expand=1, fill="both")

    encryption_tab = tk.Frame(tab_control)
    tab_control.add(encryption_tab, text="Encryption")

    decryption_tab = tk.Frame(tab_control)
    tab_control.add(decryption_tab, text="Decryption")

    # Create encryption window
    encryption_window = EncryptionWindow(encryption_tab, secure_messaging_tool)

    # Create decryption window
    decryption_window = DecryptionWindow(decryption_tab, secure_messaging_tool)

    root.mainloop()
