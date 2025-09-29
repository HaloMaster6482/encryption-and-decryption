# Import necessary modules
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import hashlib
import json
import os
import secrets
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import time
from pathlib import Path

# Try to import GUI password input
def get_password_input(prompt="Enter password:"):
    """Try multiple methods for password input"""
    # Method 1: Try tkinter GUI
    try:
        import tkinter as tk
        from tkinter import simpledialog
        
        root = tk.Tk()
        root.withdraw()  # Hide main window
        
        password = simpledialog.askstring(
            "Password Required", 
            prompt, 
            show='*'
        )
        
        root.destroy()
        return password
        
    except ImportError:
        pass
    
    # Method 2: Try getpass (hidden input)
    try:
        import getpass
        return getpass.getpass(f"{prompt} ")
    except:
        pass
    
    # Method 3: Regular input with warning
    print("⚠️  Password will be visible while typing")
    return input(f"{prompt} ")

def generate_key_from_password(password, salt=None):
    """Generate encryption key from password using PBKDF2"""
    if salt is None:
        salt = secrets.token_bytes(32)  # Generate random salt
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # Strong iteration count
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

# Password management for individual files (legacy compatibility)
def hash_password(password):
    """Create SHA-256 hash of password"""
    return hashlib.sha256(password.encode()).hexdigest()

def save_file_salt(encrypted_file_path, salt, salt_db_file="file_salts.json"):
    """Save salt for password-protected file"""
    try:
        # Load existing salt database
        if os.path.exists(salt_db_file):
            with open(salt_db_file, 'r') as f:
                salt_db = json.load(f)
        else:
            salt_db = {}
        
        # Convert salt bytes to base64 string for JSON storage
        salt_b64 = base64.b64encode(salt).decode()
        salt_db[encrypted_file_path] = salt_b64
        
        # Save updated database
        with open(salt_db_file, 'w') as f:
            json.dump(salt_db, f, indent=2)
        
        return True
    except Exception as e:
        print(f"Error saving salt: {e}")
        return False

def load_file_salt(encrypted_file_path, salt_db_file="file_salts.json"):
    """Load salt for password-protected file"""
    try:
        if not os.path.exists(salt_db_file):
            return None
        
        with open(salt_db_file, 'r') as f:
            salt_db = json.load(f)
        
        if encrypted_file_path not in salt_db:
            return None
        
        # Convert base64 string back to bytes
        salt_b64 = salt_db[encrypted_file_path]
        return base64.b64decode(salt_b64.encode())
    except Exception as e:
        print(f"Error loading salt: {e}")
        return None

def save_file_password(encrypted_file_path, password, password_db_file="file_passwords.json"):
    """Save password hash for a specific encrypted file"""
    try:
        # Load existing password database
        if os.path.exists(password_db_file):
            with open(password_db_file, 'r') as f:
                password_db = json.load(f)
        else:
            password_db = {}
        
        # Add new password entry
        password_hash = hash_password(password)
        password_db[encrypted_file_path] = password_hash
        
        # Save updated database
        with open(password_db_file, 'w') as f:
            json.dump(password_db, f, indent=2)
        
        return True
    except Exception as e:
        print(f"Error saving password for file: {e}")
        return False

def verify_file_password(encrypted_file_path, entered_password, password_db_file="file_passwords.json"):
    """Verify password for a specific encrypted file"""
    try:
        if not os.path.exists(password_db_file):
            print("❌ No password database found. File may not have a password set.")
            return False
        
        with open(password_db_file, 'r') as f:
            password_db = json.load(f)
        
        if encrypted_file_path not in password_db:
            print("❌ No password found for this file. File may not be password-protected.")
            return False
        
        stored_hash = password_db[encrypted_file_path]
        entered_hash = hash_password(entered_password)
        
        return stored_hash == entered_hash
    except Exception as e:
        print(f"Error verifying password: {e}")
        return False

def get_file_password(action="encrypt"):
    """Get password from user for file operations"""
    if action == "encrypt":
        print("\n🔐 PASSWORD SETUP FOR THIS FILE")
        print("-" * 40)
        while True:
            password = get_password_input("Create password for this file:")
            if password is None:
                print("❌ Password entry cancelled.")
                return None
            if len(password) < 3:
                print("❌ Password must be at least 3 characters long.")
                continue
            
            confirm = get_password_input("Confirm password:")
            if confirm is None:
                print("❌ Password confirmation cancelled.")
                return None
            if password != confirm:
                print("❌ Passwords don't match. Try again.")
                continue
            
            print("✅ Password set successfully!")
            return password
    else:  # decrypt
        print("\n🔐 PASSWORD REQUIRED FOR DECRYPTION")
        print("-" * 40)
        password = get_password_input("Enter password for this file:")
        return password

def view_protected_files(password_db_file="file_passwords.json"):
    """Display list of password-protected files"""
    try:
        if not os.path.exists(password_db_file):
            print("📝 No password-protected files found.")
            return
        
        with open(password_db_file, 'r') as f:
            password_db = json.load(f)
        
        if not password_db:
            print("📝 No password-protected files found.")
            return
        
        print("\n🔐 PASSWORD-PROTECTED FILES:")
        print("=" * 50)
        for i, filepath in enumerate(password_db.keys(), 1):
            exists = "✅" if os.path.exists(filepath) else "❌ (missing)"
            print(f"{i}. {filepath} {exists}")
        print("=" * 50)
        
    except Exception as e:
        print(f"Error reading protected files list: {e}")

# Function to generate a new encryption key
def generate_key():
    return Fernet.generate_key()

def save_key(key, filename):
    try:
        with open(filename, 'wb') as key_file:
            key_file.write(key)
        return True
    except PermissionError:
        print(f"Error: Permission denied when trying to save key to '{filename}'")
        return False
    except OSError as e:
        print(f"Error: Could not save key file: {e}")
        return False

def load_key(filename):
    try:
        with open(filename, 'rb') as key_file:
            return key_file.read()
    except FileNotFoundError:
        print(f"Error: Key file '{filename}' not found. Generate a key first (option 1).")
        return None
    except PermissionError:
        print(f"Error: Permission denied when trying to read key file '{filename}'")
        return None
    except OSError as e:
        print(f"Error: Could not load key file: {e}")
        return None
    
def encrypt_message(message, key):
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message

def encrypt_file(input_filename, output_filename, key, use_password=False):
    try:
        with open(input_filename, 'rb') as file:
            file_data = file.read()
        
        # Use password-based encryption if password is required
        if use_password:
            password = get_file_password("encrypt")
            if password is None:
                print("❌ Password setup cancelled. File encrypted without password protection.")
                # Fall back to regular encryption
                fernet = Fernet(key)
                encrypted_data = fernet.encrypt(file_data)
            else:
                # Generate password-based key
                password_key, salt = generate_key_from_password(password)
                fernet = Fernet(password_key)
                encrypted_data = fernet.encrypt(file_data)
                
                # Save salt for this file
                if save_file_salt(output_filename, salt):
                    print(f"🔐 Password protection enabled for {output_filename}")
                    # Also save to old database for compatibility
                    save_file_password(output_filename, password)
                else:
                    print("⚠️ File encrypted but salt saving failed")
        else:
            # Regular encryption with main key
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(file_data)
        
        with open(output_filename, 'wb') as file:
            file.write(encrypted_data)
        
        return True
    except FileNotFoundError:
        print(f"Error: Input file '{input_filename}' not found.")
        return False
    except PermissionError:
        print(f"Error: Permission denied when accessing files.")
        return False
    except IsADirectoryError:
        print(f"Error: '{input_filename}' is a directory, not a file.")
        return False
    except OSError as e:
        print(f"Error: File operation failed: {e}")
        return False

def decrypt_file(input_filename, output_filename, key, check_password=False):
    try:
        # Check if this file has password protection (has a salt)
        salt = load_file_salt(input_filename)
        
        if salt is not None:  # File is password-protected
            print("🔐 This file is password-protected!")
            password = get_file_password("decrypt")
            if password is None:
                print("❌ Password entry cancelled. Decryption cancelled.")
                return False
            
            # Generate the same key using password and salt
            try:
                password_key, _ = generate_key_from_password(password, salt)
                fernet = Fernet(password_key)
            except Exception:
                print("❌ Failed to generate key from password!")
                return False
        else:
            # File is not password-protected, use regular key
            if check_password:
                print("⚠️ File is not password-protected, using regular decryption.")
            fernet = Fernet(key)
        
        # Decrypt the file
        with open(input_filename, 'rb') as file:
            encrypted_data = file.read()
        
        try:
            decrypted_data = fernet.decrypt(encrypted_data)
        except Exception as e:
            if salt is not None:
                print("❌ Incorrect password! Decryption failed.")
            else:
                print(f"❌ Decryption failed: {e}")
            return False
        
        with open(output_filename, 'wb') as file:
            file.write(decrypted_data)
        
        if salt is not None:
            print("✅ Password verified! File decrypted successfully.")
        
        return True
    except FileNotFoundError:
        print(f"Error: Encrypted file '{input_filename}' not found.")
        return False
    except PermissionError:
        print(f"Error: Permission denied when accessing files.")
        return False
    except IsADirectoryError:
        print(f"Error: '{input_filename}' is a directory, not a file.")
        return False
    except OSError as e:
        print(f"Error: File operation failed: {e}")
        return False

def encrypt_file_with_password(input_filename, output_filename, key, password):
    """Encrypt file with a pre-provided password (for folder encryption)"""
    try:
        with open(input_filename, 'rb') as file:
            file_data = file.read()
        
        # Generate password-based key
        password_key, salt = generate_key_from_password(password)
        fernet = Fernet(password_key)
        encrypted_data = fernet.encrypt(file_data)
        
        with open(output_filename, 'wb') as file:
            file.write(encrypted_data)
        
        # Save salt for this file
        if save_file_salt(output_filename, salt):
            # Also save to old database for compatibility
            save_file_password(output_filename, password)
        
        return True
    except Exception as e:
        print(f"Error encrypting {input_filename}: {e}")
        return False

# Folder encryption functions
def encrypt_folder(input_folder, output_folder, key, use_password=False):
    """Encrypt all files in a folder individually"""
    try:
        if not os.path.exists(input_folder):
            print(f"Error: Input folder '{input_folder}' does not exist.")
            return False
        
        # Create output folder if it doesn't exist
        os.makedirs(output_folder, exist_ok=True)
        
        encrypted_count = 0
        failed_count = 0
        folder_password = None
        
        # If using password protection, get password once for the whole folder
        if use_password:
            print(f"\n🔐 PASSWORD PROTECTION FOR FOLDER: {os.path.basename(input_folder)}")
            print("-" * 60)
            folder_password = get_file_password("encrypt")
            if folder_password is None:
                print("❌ Password setup cancelled. Folder will be encrypted without password protection.")
                use_password = False
            else:
                print(f"✅ Password will be applied to all files in the folder.")
        
        # Walk through all files in the folder
        for root, dirs, files in os.walk(input_folder):
            for file in files:
                input_file_path = os.path.join(root, file)
                
                # Create corresponding output path
                relative_path = os.path.relpath(input_file_path, input_folder)
                output_file_path = os.path.join(output_folder, relative_path + '.enc')
                
                # Create output subdirectory if needed
                output_dir = os.path.dirname(output_file_path)
                os.makedirs(output_dir, exist_ok=True)
                
                print(f"Encrypting: {relative_path}")
                
                # Use folder-level password handling
                if use_password and folder_password:
                    success = encrypt_file_with_password(input_file_path, output_file_path, key, folder_password)
                else:
                    success = encrypt_file(input_file_path, output_file_path, key, use_password=False)
                
                if success:
                    encrypted_count += 1
                else:
                    failed_count += 1
        
        print(f"\n✅ Folder encryption completed!")
        print(f"Files encrypted: {encrypted_count}")
        if failed_count > 0:
            print(f"Files failed: {failed_count}")
        
        return True
        
    except Exception as e:
        print(f"Error during folder encryption: {e}")
        return False

def decrypt_folder(input_folder, output_folder, key):
    """Decrypt all encrypted files in a folder"""
    try:
        if not os.path.exists(input_folder):
            print(f"Error: Input folder '{input_folder}' does not exist.")
            return False
        
        # Create output folder if it doesn't exist
        os.makedirs(output_folder, exist_ok=True)
        
        decrypted_count = 0
        failed_count = 0
        
        # Walk through all files in the folder
        for root, dirs, files in os.walk(input_folder):
            for file in files:
                if file.endswith('.enc'):  # Only process encrypted files
                    input_file_path = os.path.join(root, file)
                    
                    # Create corresponding output path (remove .enc extension)
                    relative_path = os.path.relpath(input_file_path, input_folder)
                    output_file_path = os.path.join(output_folder, relative_path[:-4])  # Remove .enc
                    
                    # Create output subdirectory if needed
                    output_dir = os.path.dirname(output_file_path)
                    os.makedirs(output_dir, exist_ok=True)
                    
                    print(f"Decrypting: {relative_path}")
                    
                    if decrypt_file(input_file_path, output_file_path, key, check_password=True):
                        decrypted_count += 1
                    else:
                        failed_count += 1
        
        print(f"\n✅ Folder decryption completed!")
        print(f"Files decrypted: {decrypted_count}")
        if failed_count > 0:
            print(f"Files failed: {failed_count}")
        
        return True
        
    except Exception as e:
        print(f"Error during folder decryption: {e}")
        return False

def display_menu():
    print("\n" + "="*60)
    print("🔐 SECURE ENCRYPTION & DECRYPTION TOOL")
    print("="*60)
    print("1. Generate Key")
    print("2. Encrypt Message")
    print("3. Decrypt Message")
    print("4. Encrypt File (No Password)")
    print("5. Decrypt File")
    print("6. Encrypt File (With Password Protection)")
    print("7. View Protected Files")
    print("8. Exit")
    print("="*60)
    print("💡 Note: Passwords will be visible when typing")
    choice = input("Enter choice (1-8): ")
    return choice

def get_user_message():
    message = input("Enter the message: ")
    return message

def main():
    print("🔐 Welcome to the SECURE Encryption & Decryption Tool!")
    print("This version supports individual passwords for each encrypted file!")
    
    while True:
        choice = display_menu()
        
        if choice == '1':
            key = generate_key()
            if save_key(key, "secret.key"):
                print("✅ Key generated and saved to secret.key")
            else:
                print("❌ Failed to save key.")
                
        elif choice == '2':
            key = load_key("secret.key")
            if key is not None:
                message = get_user_message()
                encrypted = encrypt_message(message, key)
                print(f"✅ Encrypted message: {encrypted}")
                
        elif choice == '3':
            key = load_key("secret.key")
            if key is not None:
                encrypted_message = input("Enter the encrypted message: ").encode()
                try:
                    decrypted = decrypt_message(encrypted_message, key)
                    print(f"✅ Decrypted message: {decrypted}")
                except Exception as e:
                    print(f"❌ Decryption failed: {e}")
                    
        elif choice == '4':
            key = load_key("secret.key")
            if key is not None:
                input_file = input("Enter the input file path: ")
                output_file = input("Enter the output file path: ")
                if encrypt_file(input_file, output_file, key, use_password=False):
                    print(f"✅ File encrypted and saved to {output_file}")
                    
        elif choice == '5':
            key = load_key("secret.key")
            if key is not None:
                input_file = input("Enter the encrypted file path: ")
                output_file = input("Enter the output file path: ")
                if decrypt_file(input_file, output_file, key, check_password=False):
                    print(f"✅ File decrypted and saved to {output_file}")
                    
        elif choice == '6':
            key = load_key("secret.key")
            if key is not None:
                input_file = input("Enter the input file path: ")
                output_file = input("Enter the output file path: ")
                print("🔐 This file will be password-protected!")
                if encrypt_file(input_file, output_file, key, use_password=True):
                    print(f"✅ Password-protected file encrypted and saved to {output_file}")

        elif choice == '7':
            view_protected_files()

        elif choice == '8':
            print("🔒 Exiting the Secure Encryption Tool. Goodbye!")
            break
            
        else:
            print("❌ Invalid choice. Please try again.")


# ========================================
# GUI APPLICATION CLASS
# ========================================

class SecureEncryptionGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔐 Secure Encryption Tool by Tavish")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Load or generate encryption key
        self.key = load_key("secret.key")
        if self.key is None:
            # If no key exists, generate one
            self.key = generate_key()
            if not save_key(self.key, "secret.key"):
                messagebox.showerror("Error", "Failed to generate encryption key!")
                self.root.destroy()
                return
            messagebox.showinfo("New Key Generated", "A new encryption key has been generated and saved as 'secret.key'")
        
        # Configure styles
        self.setup_styles()
        
        # Create GUI components
        self.create_widgets()
        
        # Center the window
        self.center_window()
    
    def setup_styles(self):
        """Configure custom styles for the GUI"""
        style = ttk.Style()
        
        # Configure notebook style
        style.configure('TNotebook', tabposition='n')
        style.configure('TNotebook.Tab', padding=[20, 10])
        
        # Configure button styles
        style.configure('Action.TButton', font=('Arial', 10, 'bold'))
        style.configure('Success.TButton', background='#4CAF50')
        style.configure('Warning.TButton', background='#FF9800')
        style.configure('Danger.TButton', background='#F44336')
    
    def center_window(self):
        """Center the window on the screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def create_widgets(self):
        """Create all GUI widgets"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="🔐 Secure Encryption Tool", 
                               font=('Arial', 18, 'bold'))
        title_label.grid(row=0, column=0, pady=(0, 20))
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create tabs
        self.create_file_tab()
        self.create_folder_tab()
        self.create_message_tab()
        self.create_settings_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        status_frame.columnconfigure(1, weight=1)
        
        ttk.Label(status_frame, text="Status:").grid(row=0, column=0, sticky=tk.W)
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var)
        self.status_label.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        
        # Progress bar
        self.progress = ttk.Progressbar(status_frame, mode='determinate')
        self.progress.grid(row=0, column=2, sticky=tk.E, padx=(20, 0))
    
    def create_file_tab(self):
        """Create the file encryption/decryption tab"""
        file_frame = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(file_frame, text="📁 Files")
        
        # Configure grid
        file_frame.columnconfigure(1, weight=1)
        
        # File selection section
        file_section = ttk.LabelFrame(file_frame, text="File Selection", padding="10")
        file_section.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 15))
        file_section.columnconfigure(1, weight=1)
        
        # Input file
        ttk.Label(file_section, text="Input File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.input_file_var = tk.StringVar()
        ttk.Entry(file_section, textvariable=self.input_file_var, width=50).grid(
            row=0, column=1, sticky=(tk.W, tk.E), padx=(10, 5), pady=5)
        ttk.Button(file_section, text="Browse", 
                  command=self.browse_input_file).grid(row=0, column=2, pady=5)
        
        # Output file
        ttk.Label(file_section, text="Output File:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.output_file_var = tk.StringVar()
        ttk.Entry(file_section, textvariable=self.output_file_var, width=50).grid(
            row=1, column=1, sticky=(tk.W, tk.E), padx=(10, 5), pady=5)
        ttk.Button(file_section, text="Browse", 
                  command=self.browse_output_file).grid(row=1, column=2, pady=5)
        
        # Options section
        options_section = ttk.LabelFrame(file_frame, text="Options", padding="10")
        options_section.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 15))
        
        self.use_password_var = tk.BooleanVar()
        ttk.Checkbutton(options_section, text="🔐 Use password protection", 
                       variable=self.use_password_var).grid(row=0, column=0, sticky=tk.W)
        
        # Action buttons
        button_frame = ttk.Frame(file_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=(0, 15))
        
        ttk.Button(button_frame, text="🔒 Encrypt File", 
                  command=self.encrypt_file_gui, style='Action.TButton').grid(
                  row=0, column=0, padx=(0, 10))
        ttk.Button(button_frame, text="🔓 Decrypt File", 
                  command=self.decrypt_file_gui, style='Action.TButton').grid(
                  row=0, column=1, padx=(10, 0))
        
        # Log area
        log_section = ttk.LabelFrame(file_frame, text="Operation Log", padding="10")
        log_section.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_section.columnconfigure(0, weight=1)
        log_section.rowconfigure(0, weight=1)
        
        self.file_log = scrolledtext.ScrolledText(log_section, height=8, width=80)
        self.file_log.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        file_frame.rowconfigure(3, weight=1)
    
    def create_folder_tab(self):
        """Create the folder encryption/decryption tab"""
        folder_frame = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(folder_frame, text="📂 Folders")
        
        # Configure grid
        folder_frame.columnconfigure(1, weight=1)
        
        # Folder selection section
        folder_section = ttk.LabelFrame(folder_frame, text="Folder Selection", padding="10")
        folder_section.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 15))
        folder_section.columnconfigure(1, weight=1)
        
        # Input folder
        ttk.Label(folder_section, text="Input Folder:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.input_folder_var = tk.StringVar()
        ttk.Entry(folder_section, textvariable=self.input_folder_var, width=50).grid(
            row=0, column=1, sticky=(tk.W, tk.E), padx=(10, 5), pady=5)
        ttk.Button(folder_section, text="Browse", 
                  command=self.browse_input_folder).grid(row=0, column=2, pady=5)
        
        # Output folder
        ttk.Label(folder_section, text="Output Folder:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.output_folder_var = tk.StringVar()
        ttk.Entry(folder_section, textvariable=self.output_folder_var, width=50).grid(
            row=1, column=1, sticky=(tk.W, tk.E), padx=(10, 5), pady=5)
        ttk.Button(folder_section, text="Browse", 
                  command=self.browse_output_folder).grid(row=1, column=2, pady=5)
        
        # Folder options
        folder_options = ttk.LabelFrame(folder_frame, text="Options", padding="10")
        folder_options.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 15))
        
        self.folder_password_var = tk.BooleanVar()
        ttk.Checkbutton(folder_options, text="🔐 Use password protection for each file", 
                       variable=self.folder_password_var).grid(row=0, column=0, sticky=tk.W)
        
        # Action buttons
        folder_button_frame = ttk.Frame(folder_frame)
        folder_button_frame.grid(row=2, column=0, columnspan=3, pady=(0, 15))
        
        ttk.Button(folder_button_frame, text="🔒 Encrypt Folder", 
                  command=self.encrypt_folder_gui, style='Action.TButton').grid(
                  row=0, column=0, padx=(0, 10))
        ttk.Button(folder_button_frame, text="🔓 Decrypt Folder", 
                  command=self.decrypt_folder_gui, style='Action.TButton').grid(
                  row=0, column=1, padx=(10, 0))
        
        # Folder log area
        folder_log_section = ttk.LabelFrame(folder_frame, text="Operation Log", padding="10")
        folder_log_section.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        folder_log_section.columnconfigure(0, weight=1)
        folder_log_section.rowconfigure(0, weight=1)
        
        self.folder_log = scrolledtext.ScrolledText(folder_log_section, height=8, width=80)
        self.folder_log.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        folder_frame.rowconfigure(3, weight=1)
    
    def create_message_tab(self):
        """Create the message encryption/decryption tab"""
        message_frame = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(message_frame, text="💬 Messages")
        
        # Input section
        input_section = ttk.LabelFrame(message_frame, text="Input Message", padding="10")
        input_section.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 15))
        input_section.columnconfigure(0, weight=1)
        input_section.rowconfigure(0, weight=1)
        
        self.message_input = scrolledtext.ScrolledText(input_section, height=8, width=80)
        self.message_input.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Message action buttons
        message_button_frame = ttk.Frame(message_frame)
        message_button_frame.grid(row=1, column=0, pady=(0, 15))
        
        ttk.Button(message_button_frame, text="🔒 Encrypt Message", 
                  command=self.encrypt_message_gui, style='Action.TButton').grid(
                  row=0, column=0, padx=(0, 10))
        ttk.Button(message_button_frame, text="🔓 Decrypt Message", 
                  command=self.decrypt_message_gui, style='Action.TButton').grid(
                  row=0, column=1, padx=(10, 0))
        ttk.Button(message_button_frame, text="🗑️ Clear", 
                  command=self.clear_messages).grid(row=0, column=2, padx=(10, 0))
        
        # Output section
        output_section = ttk.LabelFrame(message_frame, text="Output", padding="10")
        output_section.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        output_section.columnconfigure(0, weight=1)
        output_section.rowconfigure(0, weight=1)
        
        self.message_output = scrolledtext.ScrolledText(output_section, height=8, width=80)
        self.message_output.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        message_frame.columnconfigure(0, weight=1)
        message_frame.rowconfigure(0, weight=1)
        message_frame.rowconfigure(2, weight=1)
    
    def create_settings_tab(self):
        """Create the settings and information tab"""
        settings_frame = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(settings_frame, text="⚙️ Settings")
        
        # Key information section
        key_section = ttk.LabelFrame(settings_frame, text="Encryption Key Information", padding="10")
        key_section.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        key_section.columnconfigure(1, weight=1)
        
        ttk.Label(key_section, text="Key File Location:").grid(row=0, column=0, sticky=tk.W, pady=5)
        key_path = "secret.key" if os.path.exists("secret.key") else "Not found"
        ttk.Label(key_section, text=key_path, font=('Courier', 9)).grid(
            row=0, column=1, sticky=tk.W, padx=(10, 0), pady=5)
        
        ttk.Button(key_section, text="Generate New Key", 
                  command=self.generate_new_key).grid(row=1, column=0, columnspan=2, pady=10)
        
        # Protected files section
        files_section = ttk.LabelFrame(settings_frame, text="Protected Files", padding="10")
        files_section.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 15))
        files_section.columnconfigure(0, weight=1)
        files_section.rowconfigure(1, weight=1)
        
        ttk.Button(files_section, text="🔍 View Protected Files", 
                  command=self.show_protected_files).grid(row=0, column=0, pady=(0, 10))
        
        self.protected_files_list = scrolledtext.ScrolledText(files_section, height=10, width=80)
        self.protected_files_list.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # About section
        about_section = ttk.LabelFrame(settings_frame, text="About", padding="10")
        about_section.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        
        about_text = """🔐 Secure Encryption Tool
        
• Uses Fernet symmetric encryption (AES 128)
• Password-based key derivation with PBKDF2
• Secure salt generation and storage
• Individual file and folder encryption
• GUI and command-line interfaces"""
        
        ttk.Label(about_section, text=about_text, justify=tk.LEFT).grid(row=0, column=0, sticky=tk.W)
        
        settings_frame.columnconfigure(0, weight=1)
        settings_frame.rowconfigure(1, weight=1)
    
    def log_message(self, tab, message):
        """Add a message to the specified log area"""
        timestamp = time.strftime("%H:%M:%S")
        log_widget = None
        
        if tab == "file":
            log_widget = self.file_log
        elif tab == "folder":
            log_widget = self.folder_log
        
        if log_widget:
            log_widget.insert(tk.END, f"[{timestamp}] {message}\n")
            log_widget.see(tk.END)
    
    def update_status(self, message, progress=None):
        """Update the status bar and progress"""
        self.status_var.set(message)
        if progress is not None:
            self.progress['value'] = progress
        self.root.update_idletasks()
    
    # File browser methods
    def browse_input_file(self):
        """Browse for input file"""
        filename = filedialog.askopenfilename(
            title="Select file to encrypt/decrypt",
            filetypes=[("All files", "*.*"), ("Text files", "*.txt"), ("Encrypted files", "*.enc")]
        )
        if filename:
            self.input_file_var.set(filename)
            # Auto-suggest output filename
            path = Path(filename)
            if not self.output_file_var.get():
                if path.suffix == '.enc':
                    # For decryption, remove .enc extension
                    suggested = str(path.with_suffix(''))
                else:
                    # For encryption, add .enc extension
                    suggested = str(path.with_suffix(path.suffix + '.enc'))
                self.output_file_var.set(suggested)
    
    def browse_output_file(self):
        """Browse for output file location"""
        filename = filedialog.asksaveasfilename(
            title="Save encrypted/decrypted file as",
            filetypes=[("All files", "*.*"), ("Encrypted files", "*.enc")]
        )
        if filename:
            self.output_file_var.set(filename)
    
    def browse_input_folder(self):
        """Browse for input folder"""
        foldername = filedialog.askdirectory(title="Select folder to encrypt/decrypt")
        if foldername:
            self.input_folder_var.set(foldername)
            # Auto-suggest output folder
            if not self.output_folder_var.get():
                path = Path(foldername)
                if path.name.endswith('_encrypted'):
                    suggested = str(path.parent / path.name.replace('_encrypted', '_decrypted'))
                else:
                    suggested = str(path.parent / (path.name + '_encrypted'))
                self.output_folder_var.set(suggested)
    
    def browse_output_folder(self):
        """Browse for output folder location"""
        foldername = filedialog.askdirectory(title="Select output folder location")
        if foldername:
            self.output_folder_var.set(foldername)
    
    # File operation methods
    def encrypt_file_gui(self):
        """Encrypt file using GUI"""
        input_file = self.input_file_var.get().strip()
        output_file = self.output_file_var.get().strip()
        
        if not input_file or not output_file:
            messagebox.showerror("Error", "Please select both input and output files.")
            return
        
        if not os.path.exists(input_file):
            messagebox.showerror("Error", f"Input file does not exist: {input_file}")
            return
        
        def encrypt_thread():
            try:
                self.update_status("Encrypting file...", 20)
                self.log_message("file", f"Starting encryption of: {input_file}")
                
                use_password = self.use_password_var.get()
                success = encrypt_file(input_file, output_file, self.key, use_password)
                
                if success:
                    self.update_status("Encryption completed", 100)
                    self.log_message("file", f"✅ File encrypted successfully: {output_file}")
                    messagebox.showinfo("Success", f"File encrypted successfully!\nSaved to: {output_file}")
                else:
                    self.update_status("Encryption failed", 0)
                    self.log_message("file", "❌ Encryption failed")
                    messagebox.showerror("Error", "File encryption failed.")
                
            except Exception as e:
                self.update_status("Encryption error", 0)
                self.log_message("file", f"❌ Encryption error: {str(e)}")
                messagebox.showerror("Error", f"Encryption error: {str(e)}")
            finally:
                self.progress['value'] = 0
        
        # Run in separate thread to prevent GUI freezing
        threading.Thread(target=encrypt_thread, daemon=True).start()
    
    def decrypt_file_gui(self):
        """Decrypt file using GUI"""
        input_file = self.input_file_var.get().strip()
        output_file = self.output_file_var.get().strip()
        
        if not input_file or not output_file:
            messagebox.showerror("Error", "Please select both input and output files.")
            return
        
        if not os.path.exists(input_file):
            messagebox.showerror("Error", f"Input file does not exist: {input_file}")
            return
        
        def decrypt_thread():
            try:
                self.update_status("Decrypting file...", 20)
                self.log_message("file", f"Starting decryption of: {input_file}")
                
                success = decrypt_file(input_file, output_file, self.key, check_password=True)
                
                if success:
                    self.update_status("Decryption completed", 100)
                    self.log_message("file", f"✅ File decrypted successfully: {output_file}")
                    messagebox.showinfo("Success", f"File decrypted successfully!\nSaved to: {output_file}")
                else:
                    self.update_status("Decryption failed", 0)
                    self.log_message("file", "❌ Decryption failed")
                    messagebox.showerror("Error", "File decryption failed.")
                
            except Exception as e:
                self.update_status("Decryption error", 0)
                self.log_message("file", f"❌ Decryption error: {str(e)}")
                messagebox.showerror("Error", f"Decryption error: {str(e)}")
            finally:
                self.progress['value'] = 0
        
        threading.Thread(target=decrypt_thread, daemon=True).start()
    
    # Folder operation methods
    def encrypt_folder_gui(self):
        """Encrypt folder using GUI"""
        input_folder = self.input_folder_var.get().strip()
        output_folder = self.output_folder_var.get().strip()
        
        if not input_folder or not output_folder:
            messagebox.showerror("Error", "Please select both input and output folders.")
            return
        
        if not os.path.exists(input_folder):
            messagebox.showerror("Error", f"Input folder does not exist: {input_folder}")
            return
        
        # Handle password input on main thread if needed
        folder_password = None
        use_password = self.folder_password_var.get()
        
        if use_password:
            from tkinter import simpledialog
            
            # Use the main GUI window as parent for dialogs to prevent issues
            folder_password = simpledialog.askstring(
                "Folder Password", 
                f"Enter password for folder '{os.path.basename(input_folder)}':\n(This password will be used for all files in the folder)", 
                show='*',
                parent=self.root
            )
            
            if folder_password:
                # Confirm password
                confirm_password = simpledialog.askstring(
                    "Confirm Password", 
                    "Please confirm the password:", 
                    show='*',
                    parent=self.root
                )
                
                if confirm_password != folder_password:
                    messagebox.showerror("Error", "Passwords do not match!")
                    return
                
                if len(folder_password) < 3:
                    messagebox.showerror("Error", "Password must be at least 3 characters long!")
                    return
            else:
                # User cancelled password input
                result = messagebox.askyesno(
                    "No Password", 
                    "No password provided. Encrypt folder without password protection?"
                )
                if not result:
                    return  # User cancelled
                use_password = False
        
        def encrypt_folder_thread():
            try:
                self.update_status("Encrypting folder...", 10)
                self.log_message("folder", f"Starting folder encryption: {input_folder}")
                
                if use_password and folder_password:
                    self.log_message("folder", "🔐 Password protection enabled for all files in folder")
                
                # Use custom folder encryption that doesn't prompt for passwords
                success = self.encrypt_folder_with_preset_password(
                    input_folder, output_folder, self.key, use_password, folder_password
                )
                
                if success:
                    self.update_status("Folder encryption completed", 100)
                    self.log_message("folder", f"✅ Folder encrypted successfully: {output_folder}")
                    messagebox.showinfo("Success", f"Folder encrypted successfully!\nSaved to: {output_folder}")
                else:
                    self.update_status("Folder encryption failed", 0)
                    self.log_message("folder", "❌ Folder encryption failed")
                    messagebox.showerror("Error", "Folder encryption failed.")
                
            except Exception as e:
                self.update_status("Folder encryption error", 0)
                self.log_message("folder", f"❌ Folder encryption error: {str(e)}")
                messagebox.showerror("Error", f"Folder encryption error: {str(e)}")
            finally:
                self.progress['value'] = 0
        
        threading.Thread(target=encrypt_folder_thread, daemon=True).start()
    
    def encrypt_folder_with_preset_password(self, input_folder, output_folder, key, use_password=False, password=None):
        """Encrypt folder with password already obtained (for GUI use)"""
        try:
            if not os.path.exists(input_folder):
                self.log_message("folder", f"❌ Input folder does not exist: {input_folder}")
                return False
            
            # Create output folder if it doesn't exist
            os.makedirs(output_folder, exist_ok=True)
            
            encrypted_count = 0
            failed_count = 0
            
            # Walk through all files in the folder
            for root, dirs, files in os.walk(input_folder):
                for file in files:
                    input_file_path = os.path.join(root, file)
                    
                    # Create corresponding output path
                    relative_path = os.path.relpath(input_file_path, input_folder)
                    output_file_path = os.path.join(output_folder, relative_path + '.enc')
                    
                    # Create output subdirectory if needed
                    output_dir = os.path.dirname(output_file_path)
                    os.makedirs(output_dir, exist_ok=True)
                    
                    self.log_message("folder", f"Encrypting: {relative_path}")
                    
                    # Use folder-level password handling
                    if use_password and password:
                        success = encrypt_file_with_password(input_file_path, output_file_path, key, password)
                    else:
                        success = encrypt_file(input_file_path, output_file_path, key, use_password=False)
                    
                    if success:
                        encrypted_count += 1
                    else:
                        failed_count += 1
                        self.log_message("folder", f"❌ Failed to encrypt: {relative_path}")
            
            self.log_message("folder", f"Files encrypted: {encrypted_count}")
            if failed_count > 0:
                self.log_message("folder", f"Files failed: {failed_count}")
            
            return encrypted_count > 0  # Success if at least one file was encrypted
            
        except Exception as e:
            self.log_message("folder", f"❌ Error during folder encryption: {e}")
            return False
    
    def decrypt_folder_gui(self):
        """Decrypt folder using GUI"""
        input_folder = self.input_folder_var.get().strip()
        output_folder = self.output_folder_var.get().strip()
        
        if not input_folder or not output_folder:
            messagebox.showerror("Error", "Please select both input and output folders.")
            return
        
        if not os.path.exists(input_folder):
            messagebox.showerror("Error", f"Input folder does not exist: {input_folder}")
            return
        
        # Pre-collect all password-protected files and get passwords upfront
        password_protected_files = {}
        
        try:
            # Scan for password-protected files first
            for root, dirs, files in os.walk(input_folder):
                for file in files:
                    if file.endswith('.enc'):
                        input_file_path = os.path.join(root, file)
                        salt = load_file_salt(input_file_path)
                        
                        if salt is not None:  # File is password-protected
                            relative_path = os.path.relpath(input_file_path, input_folder)
                            
                            # Ask for password on main thread
                            from tkinter import simpledialog
                            password = simpledialog.askstring(
                                "Password Required", 
                                f"Enter password for:\n{relative_path}", 
                                show='*',
                                parent=self.root
                            )
                            
                            if password is None:
                                # User cancelled
                                result = messagebox.askyesno(
                                    "Skip File", 
                                    f"No password provided for {relative_path}.\nSkip this file and continue with others?"
                                )
                                if not result:
                                    return  # User cancelled entire operation
                                continue  # Skip this file
                            
                            password_protected_files[input_file_path] = password
            
        except Exception as e:
            messagebox.showerror("Error", f"Error scanning files: {str(e)}")
            return
        
        def decrypt_folder_thread():
            try:
                self.update_status("Decrypting folder...", 10)
                self.log_message("folder", f"Starting folder decryption: {input_folder}")
                
                if password_protected_files:
                    self.log_message("folder", f"Found {len(password_protected_files)} password-protected files")
                
                # Use custom folder decryption with pre-collected passwords
                success = self.decrypt_folder_with_passwords(
                    input_folder, output_folder, self.key, password_protected_files
                )
                
                if success:
                    self.update_status("Folder decryption completed", 100)
                    self.log_message("folder", f"✅ Folder decrypted successfully: {output_folder}")
                    messagebox.showinfo("Success", f"Folder decrypted successfully!\nSaved to: {output_folder}")
                else:
                    self.update_status("Folder decryption failed", 0)
                    self.log_message("folder", "❌ Folder decryption failed")
                    messagebox.showerror("Error", "Folder decryption failed.")
                
            except Exception as e:
                self.update_status("Folder decryption error", 0)
                self.log_message("folder", f"❌ Folder decryption error: {str(e)}")
                messagebox.showerror("Error", f"Folder decryption error: {str(e)}")
            finally:
                self.progress['value'] = 0
        
        threading.Thread(target=decrypt_folder_thread, daemon=True).start()
    
    def decrypt_folder_with_passwords(self, input_folder, output_folder, key, password_dict):
        """Decrypt folder with pre-collected passwords"""
        try:
            if not os.path.exists(input_folder):
                self.log_message("folder", f"❌ Input folder does not exist: {input_folder}")
                return False
            
            # Create output folder if it doesn't exist
            os.makedirs(output_folder, exist_ok=True)
            
            decrypted_count = 0
            failed_count = 0
            
            # Walk through all files in the folder
            for root, dirs, files in os.walk(input_folder):
                for file in files:
                    if file.endswith('.enc'):  # Only process encrypted files
                        input_file_path = os.path.join(root, file)
                        
                        # Create corresponding output path (remove .enc extension)
                        relative_path = os.path.relpath(input_file_path, input_folder)
                        output_file_path = os.path.join(output_folder, relative_path[:-4])  # Remove .enc
                        
                        # Create output subdirectory if needed
                        output_dir = os.path.dirname(output_file_path)
                        os.makedirs(output_dir, exist_ok=True)
                        
                        self.log_message("folder", f"Decrypting: {relative_path}")
                        
                        # Check if this file has password protection
                        salt = load_file_salt(input_file_path)
                        
                        if salt is not None and input_file_path in password_dict:
                            # Use password-based decryption
                            password = password_dict[input_file_path]
                            success = self.decrypt_file_with_password(input_file_path, output_file_path, password, salt)
                        elif salt is not None:
                            # Password-protected but no password provided (user skipped)
                            self.log_message("folder", f"⏭️  Skipped password-protected file: {relative_path}")
                            continue
                        else:
                            # Regular file decryption
                            success = self.decrypt_file_simple(input_file_path, output_file_path, key)
                        
                        if success:
                            decrypted_count += 1
                        else:
                            failed_count += 1
                            self.log_message("folder", f"❌ Failed to decrypt: {relative_path}")
            
            self.log_message("folder", f"Files decrypted: {decrypted_count}")
            if failed_count > 0:
                self.log_message("folder", f"Files failed: {failed_count}")
            
            return decrypted_count > 0  # Success if at least one file was decrypted
            
        except Exception as e:
            self.log_message("folder", f"❌ Error during folder decryption: {e}")
            return False
    
    def decrypt_file_with_password(self, input_filename, output_filename, password, salt):
        """Decrypt a single file with known password and salt"""
        try:
            # Generate the same key using password and salt
            password_key, _ = generate_key_from_password(password, salt)
            fernet = Fernet(password_key)
            
            # Decrypt the file
            with open(input_filename, 'rb') as file:
                encrypted_data = file.read()
            
            decrypted_data = fernet.decrypt(encrypted_data)
            
            with open(output_filename, 'wb') as file:
                file.write(decrypted_data)
            
            return True
            
        except Exception as e:
            self.log_message("folder", f"❌ Decryption failed for {os.path.basename(input_filename)}: {e}")
            return False
    
    def decrypt_file_simple(self, input_filename, output_filename, key):
        """Decrypt a single file without password"""
        try:
            fernet = Fernet(key)
            
            with open(input_filename, 'rb') as file:
                encrypted_data = file.read()
            
            decrypted_data = fernet.decrypt(encrypted_data)
            
            with open(output_filename, 'wb') as file:
                file.write(decrypted_data)
            
            return True
            
        except Exception as e:
            self.log_message("folder", f"❌ Decryption failed for {os.path.basename(input_filename)}: {e}")
            return False
    
    # Message operation methods
    def encrypt_message_gui(self):
        """Encrypt message using GUI"""
        message = self.message_input.get("1.0", tk.END).strip()
        
        if not message:
            messagebox.showerror("Error", "Please enter a message to encrypt.")
            return
        
        try:
            self.update_status("Encrypting message...", 50)
            encrypted = encrypt_message(message, self.key)
            
            self.message_output.delete("1.0", tk.END)
            self.message_output.insert("1.0", encrypted)
            
            self.update_status("Message encrypted", 100)
            messagebox.showinfo("Success", "Message encrypted successfully!")
            
        except Exception as e:
            self.update_status("Message encryption error", 0)
            messagebox.showerror("Error", f"Message encryption error: {str(e)}")
        finally:
            self.progress['value'] = 0
    
    def decrypt_message_gui(self):
        """Decrypt message using GUI"""
        encrypted_message = self.message_input.get("1.0", tk.END).strip()
        
        if not encrypted_message:
            messagebox.showerror("Error", "Please enter an encrypted message to decrypt.")
            return
        
        try:
            self.update_status("Decrypting message...", 50)
            decrypted = decrypt_message(encrypted_message, self.key)
            
            if decrypted:
                self.message_output.delete("1.0", tk.END)
                self.message_output.insert("1.0", decrypted)
                self.update_status("Message decrypted", 100)
                messagebox.showinfo("Success", "Message decrypted successfully!")
            else:
                self.update_status("Message decryption failed", 0)
                messagebox.showerror("Error", "Message decryption failed. Invalid encrypted message or wrong key.")
            
        except Exception as e:
            self.update_status("Message decryption error", 0)
            messagebox.showerror("Error", f"Message decryption error: {str(e)}")
        finally:
            self.progress['value'] = 0
    
    def clear_messages(self):
        """Clear both message input and output areas"""
        self.message_input.delete("1.0", tk.END)
        self.message_output.delete("1.0", tk.END)
        self.update_status("Messages cleared", 0)
    
    # Settings methods
    def generate_new_key(self):
        """Generate a new encryption key"""
        result = messagebox.askyesno(
            "Generate New Key", 
            "⚠️ Warning: Generating a new key will make all previously encrypted files unreadable!\n\nAre you sure you want to continue?"
        )
        
        if result:
            try:
                # Backup old key if it exists
                if os.path.exists("secret.key"):
                    backup_name = f"secret_backup_{int(time.time())}.key"
                    os.rename("secret.key", backup_name)
                    self.log_message("file", f"Old key backed up as: {backup_name}")
                
                # Generate new key
                new_key = generate_key()
                save_key(new_key, "secret.key")
                self.key = new_key
                
                self.update_status("New key generated", 100)
                messagebox.showinfo("Success", "New encryption key generated successfully!")
                self.log_message("file", "✅ New encryption key generated")
                
            except Exception as e:
                self.update_status("Key generation error", 0)
                messagebox.showerror("Error", f"Key generation error: {str(e)}")
            finally:
                self.progress['value'] = 0
    
    def show_protected_files(self):
        """Show list of password-protected files"""
        self.protected_files_list.delete("1.0", tk.END)
        
        # Check both old and new password systems
        protected_files = []
        
        # Check old password system
        if os.path.exists("file_passwords.json"):
            try:
                with open("file_passwords.json", 'r') as f:
                    old_db = json.load(f)
                for filepath in old_db.keys():
                    exists = "✅" if os.path.exists(filepath) else "❌ (missing)"
                    protected_files.append(f"[Legacy] {filepath} {exists}")
            except:
                pass
        
        # Check new salt system
        if os.path.exists("file_salts.json"):
            try:
                with open("file_salts.json", 'r') as f:
                    salt_db = json.load(f)
                for filepath in salt_db.keys():
                    exists = "✅" if os.path.exists(filepath) else "❌ (missing)"
                    protected_files.append(f"[Secure] {filepath} {exists}")
            except:
                pass
        
        if protected_files:
            self.protected_files_list.insert("1.0", "\n".join(protected_files))
        else:
            self.protected_files_list.insert("1.0", "No password-protected files found.")
    
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()


if __name__ == "__main__":
    # Check if GUI should be launched
    if len(os.sys.argv) > 1 and os.sys.argv[1] == "--gui":
        app = SecureEncryptionGUI()
        app.run()
    else:
        # Show menu to choose interface
        print("🔐 Secure Encryption Tool")
        print("=" * 30)
        print("1. Launch GUI Interface")
        print("2. Use Command Line Interface")
        choice = input("\nChoose interface (1 or 2): ").strip()
        
        if choice == "1":
            app = SecureEncryptionGUI()
            app.run()
        else:
            main()