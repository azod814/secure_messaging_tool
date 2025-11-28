import tkinter as tk
from tkinter import messagebox, ttk
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

class EncryptionWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption Window")
        self.secure_messaging_tool = SecureMessagingTool()

        self.message_label = tk.Label(root, text="Message:", font=("Arial", 16))
        self.message_label.pack(pady=10)

        self.message_entry = tk.Entry(root, font=("Arial", 16), width=50)
        self.message_entry.pack(pady=10)

        self.encrypt_button = tk.Button(root, text="Encrypt", font=("Arial", 16), command=self.encrypt_message)
        self.encrypt_button.pack(pady=10)

        self.encrypted_message_label = tk.Label(root, text="Encrypted Message:", font=("Arial", 16))
        self.encrypted_message_label.pack(pady=10)

        self.encrypted_message_entry = tk.Entry(root, font=("Arial", 16), width=50)
        self.encrypted_message_entry.pack(pady=10)

    def encrypt_message(self):
        message = self.message_entry.get()
        encrypted_message = self.secure_messaging_tool.encrypt_message(message)
        self.encrypted_message_entry.delete(0, tk.END)
        self.encrypted_message_entry.insert(0, encrypted_message)

class DecryptionWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Decryption Window")
        self.secure_messaging_tool = SecureMessagingTool()

        self.encrypted_message_label = tk.Label(root, text="Encrypted Message:", font=("Arial", 16))
        self.encrypted_message_label.pack(pady=10)

        self.encrypted_message_entry = tk.Entry(root, font=("Arial", 16), width=50)
        self.encrypted_message_entry.pack(pady=10)

        self.decrypt_button = tk.Button(root, text="Decrypt", font=("Arial", 16), command=self.decrypt_message)
        self.decrypt_button.pack(pady=10)

        self.decrypted_message_label = tk.Label(root, text="Decrypted Message:", font=("Arial", 16))
        self.decrypted_message_label.pack(pady=10)

        self.decrypted_message_entry = tk.Entry(root, font=("Arial", 16), width=50)
        self.decrypted_message_entry.pack(pady=10)

    def decrypt_message(self):
        encrypted_message = self.encrypted_message_entry.get()
        decrypted_message = self.secure_messaging_tool.decrypt_message(encrypted_message)
        self.decrypted_message_entry.delete(0, tk.END)
        self.decrypted_message_entry.insert(0, decrypted_message)

if __name__ == "__main__":
    root = tk.Tk()
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
    encryption_window = EncryptionWindow(encryption_tab)

    # Create decryption window
    decryption_window = DecryptionWindow(decryption_tab)

    root.mainloop()
