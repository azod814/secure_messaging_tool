import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from cryptography.fernet import Fernet, InvalidToken
import os
import pyperclip
import sys
import ctypes

# Hide terminal window (Windows)
if sys.platform == "win32":
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

class SecureMessagingTool:
    def __init__(self):
        self.key_file = "encryption_key.txt"
        try:
            if not os.path.exists(self.key_file):
                self.key = Fernet.generate_key()
                with open(self.key_file, "wb") as f:
                    f.write(self.key)
                messagebox.showinfo("Info", f"New key generated! Share {self.key_file} with your friend!")
            else:
                with open(self.key_file, "rb") as f:
                    self.key = f.read()
            self.cipher_suite = Fernet(self.key)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load key: {e}")
            sys.exit(1)

    def encrypt_message(self, message):
        encrypted_message = self.cipher_suite.encrypt(message.encode())
        return encrypted_message.decode()

    def decrypt_message(self, encrypted_message):
        try:
            decrypted_message = self.cipher_suite.decrypt(encrypted_message.encode())
            return decrypted_message.decode()
        except InvalidToken:
            raise ValueError("Invalid encrypted message or wrong key!")

    def encrypt_file(self, input_file_path, output_file_path):
        with open(input_file_path, "rb") as f:
            file_data = f.read()
        encrypted_data = self.cipher_suite.encrypt(file_data)
        with open(output_file_path, "wb") as f:
            f.write(encrypted_data)

    def decrypt_file(self, input_file_path, output_file_path):
        with open(input_file_path, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = self.cipher_suite.decrypt(encrypted_data)
        with open(output_file_path, "wb") as f:
            f.write(decrypted_data)

class EncryptionWindow:
    def __init__(self, parent, secure_messaging_tool):
        self.parent = parent
        self.secure_messaging_tool = secure_messaging_tool

        # Styling
        parent.configure(bg="#2c3e50")
        style = ttk.Style()
        style.configure("TNotebook", background="#34495e", foreground="white")
        style.configure("TFrame", background="#2c3e50")

        # Text Encryption
        self.message_label = tk.Label(
            parent, text="Enter Your Message:", font=("Helvetica", 12, "bold"),
            bg="#2c3e50", fg="white"
        )
        self.message_label.pack(pady=10)
        self.message_entry = tk.Entry(
            parent, font=("Helvetica", 12), width=50, bg="#34495e", fg="white",
            insertbackground="white"
        )
        self.message_entry.pack(pady=5)
        self.encrypt_button = tk.Button(
            parent, text="Encrypt Text", font=("Helvetica", 12, "bold"),
            bg="#3498db", fg="white", command=self.encrypt_message
        )
        self.encrypt_button.pack(pady=5)
        self.encrypted_message_label = tk.Label(
            parent, text="Encrypted Message:", font=("Helvetica", 12, "bold"),
            bg="#2c3e50", fg="white"
        )
        self.encrypted_message_label.pack(pady=5)
        self.encrypted_message_entry = tk.Entry(
            parent, font=("Helvetica", 12), width=50, bg="#34495e", fg="white",
            insertbackground="white"
        )
        self.encrypted_message_entry.pack(pady=5)
        self.copy_button = tk.Button(
            parent, text="Copy Text", font=("Helvetica", 12, "bold"),
            bg="#2ecc71", fg="white", command=self.copy_code
        )
        self.copy_button.pack(pady=5)
        self.save_button = tk.Button(
            parent, text="Save Encrypted Message", font=("Helvetica", 12, "bold"),
            bg="#e74c3c", fg="white", command=self.save_encrypted_message
        )
        self.save_button.pack(pady=5)

        # File Encryption
        self.file_label = tk.Label(
            parent, text="Select File to Encrypt:", font=("Helvetica", 12, "bold"),
            bg="#2c3e50", fg="white"
        )
        self.file_label.pack(pady=10)
        self.select_file_button = tk.Button(
            parent, text="Select File", font=("Helvetica", 12, "bold"),
            bg="#9b59b6", fg="white", command=self.select_file_to_encrypt
        )
        self.select_file_button.pack(pady=5)

    def encrypt_message(self):
        message = self.message_entry.get()
        if not message:
            messagebox.showerror("Error", "Message cannot be empty!")
            return
        encrypted_message = self.secure_messaging_tool.encrypt_message(message)
        self.encrypted_message_entry.delete(0, tk.END)
        self.encrypted_message_entry.insert(0, encrypted_message)

    def copy_code(self):
        encrypted_message = self.encrypted_message_entry.get()
        if not encrypted_message:
            messagebox.showerror("Error", "No message to copy!")
            return
        pyperclip.copy(encrypted_message)
        messagebox.showinfo("Success", "Encrypted message copied!")

    def save_encrypted_message(self):
        encrypted_message = self.encrypted_message_entry.get()
        if not encrypted_message:
            messagebox.showerror("Error", "No encrypted message to save!")
            return
        output_path = filedialog.asksaveasfilename(
            defaultextension=".enc",
            filetypes=[("Encrypted Files", "*.enc"), ("Text Files", "*.txt")]
        )
        if output_path:
            with open(output_path, "w") as f:
                f.write(encrypted_message)
            messagebox.showinfo("Success", f"Encrypted message saved to {output_path}!")

    def select_file_to_encrypt(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            output_path = filedialog.asksaveasfilename(defaultextension=".enc")
            if output_path:
                try:
                    self.secure_messaging_tool.encrypt_file(file_path, output_path)
                    messagebox.showinfo("Success", f"File encrypted and saved as {output_path}!")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to encrypt file: {e}")

class DecryptionWindow:
    def __init__(self, parent, secure_messaging_tool):
        self.parent = parent
        self.secure_messaging_tool = secure_messaging_tool

        # Styling
        parent.configure(bg="#2c3e50")

        # Text Decryption
        self.encrypted_message_label = tk.Label(
            parent, text="Enter Encrypted Message:", font=("Helvetica", 12, "bold"),
            bg="#2c3e50", fg="white"
        )
        self.encrypted_message_label.pack(pady=10)
        self.encrypted_message_entry = tk.Entry(
            parent, font=("Helvetica", 12), width=50, bg="#34495e", fg="white",
            insertbackground="white"
        )
        self.encrypted_message_entry.pack(pady=5)
        self.decrypt_button = tk.Button(
            parent, text="Decrypt Text", font=("Helvetica", 12, "bold"),
            bg="#3498db", fg="white", command=self.decrypt_message
        )
        self.decrypt_button.pack(pady=5)
        self.decrypted_message_label = tk.Label(
            parent, text="Decrypted Message:", font=("Helvetica", 12, "bold"),
            bg="#2c3e50", fg="white"
        )
        self.decrypted_message_label.pack(pady=5)
        self.decrypted_message_entry = tk.Entry(
            parent, font=("Helvetica", 12), width=50, bg="#34495e", fg="white",
            insertbackground="white"
        )
        self.decrypted_message_entry.pack(pady=5)
        self.load_button = tk.Button(
            parent, text="Load Encrypted Message", font=("Helvetica", 12, "bold"),
            bg="#e74c3c", fg="white", command=self.load_encrypted_message
        )
        self.load_button.pack(pady=5)

        # File Decryption
        self.file_label = tk.Label(
            parent, text="Select File to Decrypt:", font=("Helvetica", 12, "bold"),
            bg="#2c3e50", fg="white"
        )
        self.file_label.pack(pady=10)
        self.select_file_button = tk.Button(
            parent, text="Select File", font=("Helvetica", 12, "bold"),
            bg="#9b59b6", fg="white", command=self.select_file_to_decrypt
        )
        self.select_file_button.pack(pady=5)

    def decrypt_message(self):
        encrypted_message = self.encrypted_message_entry.get()
        if not encrypted_message:
            messagebox.showerror("Error", "Encrypted message cannot be empty!")
            return
        try:
            decrypted_message = self.secure_messaging_tool.decrypt_message(encrypted_message)
            self.decrypted_message_entry.delete(0, tk.END)
            self.decrypted_message_entry.insert(0, decrypted_message)
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def load_encrypted_message(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Encrypted Files", "*.enc"), ("Text Files", "*.txt")]
        )
        if file_path:
            with open(file_path, "r") as f:
                encrypted_message = f.read()
            self.encrypted_message_entry.delete(0, tk.END)
            self.encrypted_message_entry.insert(0, encrypted_message)

    def select_file_to_decrypt(self):
        file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
        if file_path:
            output_path = filedialog.asksaveasfilename()
            if output_path:
                try:
                    self.secure_messaging_tool.decrypt_file(file_path, output_path)
                    messagebox.showinfo("Success", f"File decrypted and saved as {output_path}!")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to decrypt file: {e}")

def show_banner():
    banner = """
                ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗██████╗
                ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗
                ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ██║  ██║
                ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ██║  ██║
                ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗██████╔╝
                ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝

                            ████████╗ ██████╗  ██████╗ ██╗
                            ╚══██╔══╝██╔═══██╗██╔═══██╗██║
                               ██║   ██║   ██║██║   ██║██║
                               ██║   ██║   ██║██║   ██║██║
                               ██║   ╚██████╔╝╚██████╔╝███████╗
                               ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
    """
    print(banner)

if __name__ == "__main__":
    show_banner()
    secure_messaging_tool = SecureMessagingTool()
    root = tk.Tk()
    root.title("Secure Messaging Tool - Professional Edition")
    root.geometry("800x600")
    root.configure(bg="#2c3e50")
    root.attributes("-alpha", 0.95)  # Transparent background

    tab_control = ttk.Notebook(root)
    tab_control.pack(expand=1, fill="both")

    encryption_tab = tk.Frame(tab_control, bg="#2c3e50")
    tab_control.add(encryption_tab, text="Encryption")

    decryption_tab = tk.Frame(tab_control, bg="#2c3e50")
    tab_control.add(decryption_tab, text="Decryption")

    encryption_window = EncryptionWindow(encryption_tab, secure_messaging_tool)
    decryption_window = DecryptionWindow(decryption_tab, secure_messaging_tool)

    root.mainloop()
