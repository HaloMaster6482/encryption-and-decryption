#!/usr/bin/env python3
"""
GUI Version of Secure Encryption & Decryption Tool
Uses tkinter for user-friendly interface with hidden password input
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from cryptography.fernet import Fernet
import hashlib
import json
import os
import threading

class SecureEncryptionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Encryption & Decryption Tool")
        self.root.geometry("600x700")
        self.root.configure(bg='#f0f0f0')
        
        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        
        self.setup_gui()
        
    def setup_gui(self):
        """Create the main GUI interface"""
        
        # Title
        title_frame = tk.Frame(self.root, bg='#2c3e50', height=80)
        title_frame.pack(fill='x', pady=(0, 20))
        
        title_label = tk.Label(
            title_frame, 
            text="🔐 SECURE ENCRYPTION TOOL",
            font=('Arial', 18, 'bold'),
            bg='#2c3e50',
            fg='white'
        )
        title_label.pack(pady=20)
        
        # Main container
        main_frame = tk.Frame(self.root, bg='#f0f0f0')
        main_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Key Management Section
        key_frame = tk.LabelFrame(main_frame, text="🔑 Key Management", font=('Arial', 12, 'bold'))
        key_frame.pack(fill='x', pady=(0, 15))
        
        tk.Button(
            key_frame, 
            text="Generate New Key",
            command=self.generate_key,
            bg='#3498db',
            fg='white',
            font=('Arial', 10, 'bold'),
            height=2
        ).pack(pady=10, padx=10, fill='x')
        
        # Message Encryption Section
        message_frame = tk.LabelFrame(main_frame, text="💬 Message Encryption", font=('Arial', 12, 'bold'))
        message_frame.pack(fill='x', pady=(0, 15))
        
        tk.Button(
            message_frame, 
            text="Encrypt Message",
            command=self.encrypt_message_gui,
            bg='#27ae60',
            fg='white',
            font=('Arial', 10, 'bold'),
            height=2
        ).pack(pady=5, padx=10, fill='x')
        
        tk.Button(
            message_frame, 
            text="Decrypt Message",
            command=self.decrypt_message_gui,
            bg='#e74c3c',
            fg='white',
            font=('Arial', 10, 'bold'),
            height=2
        ).pack(pady=5, padx=10, fill='x')
        
        # File Encryption Section
        file_frame = tk.LabelFrame(main_frame, text="📁 File Encryption", font=('Arial', 12, 'bold'))
        file_frame.pack(fill='x', pady=(0, 15))
        
        # Regular file encryption
        tk.Button(
            file_frame, 
            text="Encrypt File (No Password)",
            command=lambda: self.encrypt_file_gui(use_password=False),
            bg='#f39c12',
            fg='white',
            font=('Arial', 10, 'bold'),
            height=2
        ).pack(pady=2, padx=10, fill='x')
        
        tk.Button(
            file_frame, 
            text="Decrypt File (No Password)",
            command=lambda: self.decrypt_file_gui(check_password=False),
            bg='#d35400',
            fg='white',
            font=('Arial', 10, 'bold'),
            height=2
        ).pack(pady=2, padx=10, fill='x')
        
        # Password-protected file encryption
        tk.Button(
            file_frame, 
            text="🔐 Encrypt File (With Password)",
            command=lambda: self.encrypt_file_gui(use_password=True),
            bg='#8e44ad',
            fg='white',
            font=('Arial', 10, 'bold'),
            height=2
        ).pack(pady=2, padx=10, fill='x')
        
        tk.Button(
            file_frame, 
            text="🔓 Decrypt File (Password Required)",
            command=lambda: self.decrypt_file_gui(check_password=True),
            bg='#9b59b6',
            fg='white',
            font=('Arial', 10, 'bold'),
            height=2
        ).pack(pady=2, padx=10, fill='x')
        
        # Utilities Section
        utils_frame = tk.LabelFrame(main_frame, text="🔧 Utilities", font=('Arial', 12, 'bold'))
        utils_frame.pack(fill='x', pady=(0, 15))
        
        tk.Button(
            utils_frame, 
            text="View Protected Files",
            command=self.view_protected_files_gui,
            bg='#34495e',
            fg='white',
            font=('Arial', 10, 'bold'),
            height=2
        ).pack(pady=5, padx=10, fill='x')
        
        # Status area
        self.status_text = tk.Text(main_frame, height=8, bg='#ecf0f1', state='disabled')
        self.status_text.pack(fill='both', expand=True, pady=(0, 10))
        
        # Scrollbar for status area
        scrollbar = tk.Scrollbar(self.status_text)
        scrollbar.pack(side='right', fill='y')
        self.status_text.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.status_text.yview)
        
        self.log_message("🔐 Secure Encryption Tool loaded successfully!")
        self.log_message("💡 Click any button to get started.")
    
    def log_message(self, message):
        """Add message to status area"""
        self.status_text.config(state='normal')
        self.status_text.insert('end', f"[{self.get_timestamp()}] {message}\n")
        self.status_text.config(state='disabled')
        self.status_text.see('end')
        self.root.update()
    
    def get_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().strftime("%H:%M:%S")
    
    # Password management functions (from original code)
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def save_file_password(self, encrypted_file_path, password, password_db_file="file_passwords.json"):
        try:
            if os.path.exists(password_db_file):
                with open(password_db_file, 'r') as f:
                    password_db = json.load(f)
            else:
                password_db = {}
            
            password_hash = self.hash_password(password)
            password_db[encrypted_file_path] = password_hash
            
            with open(password_db_file, 'w') as f:
                json.dump(password_db, f, indent=2)
            
            return True
        except Exception as e:
            self.log_message(f"❌ Error saving password: {e}")
            return False
    
    def verify_file_password(self, encrypted_file_path, entered_password, password_db_file="file_passwords.json"):
        try:
            if not os.path.exists(password_db_file):
                return False
            
            with open(password_db_file, 'r') as f:
                password_db = json.load(f)
            
            if encrypted_file_path not in password_db:
                return False
            
            stored_hash = password_db[encrypted_file_path]
            entered_hash = self.hash_password(entered_password)
            
            return stored_hash == entered_hash
        except:
            return False
    
    # Core encryption functions
    def generate_key(self):
        """Generate new encryption key"""
        try:
            key = Fernet.generate_key()
            with open("secret.key", 'wb') as key_file:
                key_file.write(key)
            self.log_message("✅ New encryption key generated and saved!")
            messagebox.showinfo("Success", "New encryption key generated successfully!")
        except Exception as e:
            self.log_message(f"❌ Error generating key: {e}")
            messagebox.showerror("Error", f"Failed to generate key: {e}")
    
    def load_key(self):
        """Load encryption key"""
        try:
            with open("secret.key", 'rb') as key_file:
                return key_file.read()
        except FileNotFoundError:
            messagebox.showerror("Error", "Encryption key not found! Generate a key first.")
            return None
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load key: {e}")
            return None
    
    def encrypt_message_gui(self):
        """GUI for message encryption"""
        key = self.load_key()
        if key is None:
            return
        
        # Get message from user
        message = simpledialog.askstring("Encrypt Message", "Enter message to encrypt:")
        if message is None:
            return
        
        try:
            fernet = Fernet(key)
            encrypted_message = fernet.encrypt(message.encode())
            
            # Show encrypted message
            result_window = tk.Toplevel(self.root)
            result_window.title("Encrypted Message")
            result_window.geometry("500x300")
            
            tk.Label(result_window, text="Encrypted Message:", font=('Arial', 12, 'bold')).pack(pady=10)
            
            text_area = tk.Text(result_window, wrap='word')
            text_area.pack(fill='both', expand=True, padx=10, pady=10)
            text_area.insert('1.0', encrypted_message.decode())
            
            tk.Button(
                result_window, 
                text="Copy to Clipboard",
                command=lambda: self.copy_to_clipboard(encrypted_message.decode()),
                bg='#3498db',
                fg='white'
            ).pack(pady=10)
            
            self.log_message("✅ Message encrypted successfully!")
            
        except Exception as e:
            self.log_message(f"❌ Encryption failed: {e}")
            messagebox.showerror("Error", f"Encryption failed: {e}")
    
    def decrypt_message_gui(self):
        """GUI for message decryption"""
        key = self.load_key()
        if key is None:
            return
        
        # Get encrypted message from user
        encrypted_message = simpledialog.askstring("Decrypt Message", "Enter encrypted message:")
        if encrypted_message is None:
            return
        
        try:
            fernet = Fernet(key)
            decrypted_message = fernet.decrypt(encrypted_message.encode()).decode()
            
            # Show decrypted message
            messagebox.showinfo("Decrypted Message", f"Original message:\n\n{decrypted_message}")
            self.log_message("✅ Message decrypted successfully!")
            
        except Exception as e:
            self.log_message(f"❌ Decryption failed: {e}")
            messagebox.showerror("Error", f"Decryption failed: {e}")
    
    def encrypt_file_gui(self, use_password=False):
        """GUI for file encryption"""
        key = self.load_key()
        if key is None:
            return
        
        # Select input file
        input_file = filedialog.askopenfilename(title="Select file to encrypt")
        if not input_file:
            return
        
        # Select output file
        output_file = filedialog.asksaveasfilename(
            title="Save encrypted file as",
            defaultextension=".encrypted"
        )
        if not output_file:
            return
        
        password = None
        if use_password:
            password = self.get_password_for_encryption()
            if password is None:
                self.log_message("❌ Password setup cancelled.")
                return
        
        try:
            # Encrypt file
            with open(input_file, 'rb') as file:
                file_data = file.read()
            
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(file_data)
            
            with open(output_file, 'wb') as file:
                file.write(encrypted_data)
            
            # Save password if required
            if use_password and password:
                if self.save_file_password(output_file, password):
                    self.log_message(f"🔐 File encrypted with password protection: {output_file}")
                else:
                    self.log_message(f"⚠️ File encrypted but password saving failed: {output_file}")
            else:
                self.log_message(f"✅ File encrypted: {output_file}")
            
            messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as: {output_file}")
            
        except Exception as e:
            self.log_message(f"❌ File encryption failed: {e}")
            messagebox.showerror("Error", f"File encryption failed: {e}")
    
    def decrypt_file_gui(self, check_password=False):
        """GUI for file decryption"""
        key = self.load_key()
        if key is None:
            return
        
        # Select encrypted file
        input_file = filedialog.askopenfilename(title="Select encrypted file to decrypt")
        if not input_file:
            return
        
        # Check password if required
        if check_password:
            password = simpledialog.askstring("Password Required", "Enter password for this file:", show='*')
            if password is None:
                self.log_message("❌ Password entry cancelled.")
                return
            
            if not self.verify_file_password(input_file, password):
                self.log_message("❌ Incorrect password!")
                messagebox.showerror("Error", "Incorrect password!")
                return
            
            self.log_message("✅ Password verified!")
        
        # Select output file
        output_file = filedialog.asksaveasfilename(title="Save decrypted file as")
        if not output_file:
            return
        
        try:
            # Decrypt file
            with open(input_file, 'rb') as file:
                encrypted_data = file.read()
            
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_data)
            
            with open(output_file, 'wb') as file:
                file.write(decrypted_data)
            
            self.log_message(f"✅ File decrypted: {output_file}")
            messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as: {output_file}")
            
        except Exception as e:
            self.log_message(f"❌ File decryption failed: {e}")
            messagebox.showerror("Error", f"File decryption failed: {e}")
    
    def get_password_for_encryption(self):
        """Get password for file encryption with confirmation"""
        while True:
            password = simpledialog.askstring("Set Password", "Create password for this file:", show='*')
            if password is None:
                return None
            
            if len(password) < 3:
                messagebox.showwarning("Warning", "Password must be at least 3 characters long.")
                continue
            
            confirm = simpledialog.askstring("Confirm Password", "Confirm password:", show='*')
            if confirm is None:
                return None
            
            if password != confirm:
                messagebox.showwarning("Warning", "Passwords don't match. Try again.")
                continue
            
            return password
    
    def view_protected_files_gui(self):
        """Show list of password-protected files"""
        try:
            password_db_file = "file_passwords.json"
            if not os.path.exists(password_db_file):
                messagebox.showinfo("No Protected Files", "No password-protected files found.")
                return
            
            with open(password_db_file, 'r') as f:
                password_db = json.load(f)
            
            if not password_db:
                messagebox.showinfo("No Protected Files", "No password-protected files found.")
                return
            
            # Create window to show protected files
            files_window = tk.Toplevel(self.root)
            files_window.title("Password-Protected Files")
            files_window.geometry("600x400")
            
            tk.Label(files_window, text="🔐 PASSWORD-PROTECTED FILES", font=('Arial', 14, 'bold')).pack(pady=10)
            
            # Create listbox with scrollbar
            frame = tk.Frame(files_window)
            frame.pack(fill='both', expand=True, padx=20, pady=10)
            
            scrollbar = tk.Scrollbar(frame)
            scrollbar.pack(side='right', fill='y')
            
            listbox = tk.Listbox(frame, yscrollcommand=scrollbar.set, font=('Courier', 10))
            listbox.pack(side='left', fill='both', expand=True)
            scrollbar.config(command=listbox.yview)
            
            for filepath in password_db.keys():
                status = "✅ EXISTS" if os.path.exists(filepath) else "❌ MISSING"
                listbox.insert('end', f"{filepath} [{status}]")
            
            self.log_message(f"📋 Found {len(password_db)} password-protected files")
            
        except Exception as e:
            self.log_message(f"❌ Error reading protected files: {e}")
            messagebox.showerror("Error", f"Error reading protected files: {e}")
    
    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied", "Text copied to clipboard!")

def main():
    root = tk.Tk()
    app = SecureEncryptionGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()