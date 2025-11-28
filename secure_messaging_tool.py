import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet

class SecureMessagingTool:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)

    def encrypt_message(self, message):
        encrypted_message = self.cipher_suite.encrypt(message.encode())
        return encrypted_message.decode()

    def decrypt_message(self, encrypted_message):
        decrypted_message = self.cipher_suite.decrypt(encrypted_message.encode())
        return decrypted_message.decode()

class SecureMessagingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Messaging Tool")
        self.secure_messaging_tool = SecureMessagingTool()

        self.message_label = tk.Label(root, text="Message:")
        self.message_label.pack()

        self.message_entry = tk.Entry(root)
        self.message_entry.pack()

        self.encrypt_button = tk.Button(root, text="Encrypt", command=self.encrypt_message)
        self.encrypt_button.pack()

        self.encrypted_message_label = tk.Label(root, text="Encrypted Message:")
        self.encrypted_message_label.pack()

        self.encrypted_message_entry = tk.Entry(root)
        self.encrypted_message_entry.pack()

        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt_message)
        self.decrypt_button.pack()

        self.decrypted_message_label = tk.Label(root, text="Decrypted Message:")
        self.decrypted_message_label.pack()

        self.decrypted_message_entry = tk.Entry(root)
        self.decrypted_message_entry.pack()

    def encrypt_message(self):
        message = self.message_entry.get()
        encrypted_message = self.secure_messaging_tool.encrypt_message(message)
        self.encrypted_message_entry.delete(0, tk.END)
        self.encrypted_message_entry.insert(0, encrypted_message)

    def decrypt_message(self):
        encrypted_message = self.encrypted_message_entry.get()
        decrypted_message = self.secure_messaging_tool.decrypt_message(encrypted_message)
        self.decrypted_message_entry.delete(0, tk.END)
        self.decrypted_message_entry.insert(0, decrypted_message)

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureMessagingApp(root)
    root.mainloop()
