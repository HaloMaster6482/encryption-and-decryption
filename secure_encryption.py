# Import necessary modules
from cryptography.fernet import Fernet
import hashlib
import json
import os

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

# Password management for individual files
def hash_password(password):
    """Create SHA-256 hash of password"""
    return hashlib.sha256(password.encode()).hexdigest()

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
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(file_data)
        with open(output_filename, 'wb') as file:
            file.write(encrypted_data)
        
        # If password protection is enabled, save the password
        if use_password:
            password = get_file_password("encrypt")
            if password is None:
                print("❌ Password setup cancelled. File encrypted without password protection.")
                return True
            if save_file_password(output_filename, password):
                print(f"🔐 Password protection enabled for {output_filename}")
            else:
                print("⚠️ File encrypted but password saving failed")
        
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
        # Check password if required
        if check_password:
            password = get_file_password("decrypt")
            if password is None:
                print("❌ Password entry cancelled. Decryption cancelled.")
                return False
            if not verify_file_password(input_filename, password):
                print("❌ Incorrect password! Decryption cancelled.")
                return False
            print("✅ Password verified!")
        
        with open(input_filename, 'rb') as file:
            encrypted_data = file.read()
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        with open(output_filename, 'wb') as file:
            file.write(decrypted_data)
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

def display_menu():
    print("\n" + "="*60)
    print("🔐 SECURE ENCRYPTION & DECRYPTION TOOL")
    print("="*60)
    print("1. Generate Key")
    print("2. Encrypt Message")
    print("3. Decrypt Message")
    print("4. Encrypt File (No Password)")
    print("5. Decrypt File (No Password)")
    print("6. Encrypt File (With Password Protection)")
    print("7. Decrypt File (Password Protected)")
    print("8. View Protected Files")
    print("9. Exit")
    print("="*60)
    print("💡 Note: Passwords will be visible when typing")
    choice = input("Enter choice (1-9): ")
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
            key = load_key("secret.key")
            if key is not None:
                input_file = input("Enter the encrypted file path: ")
                output_file = input("Enter the output file path: ")
                print("🔐 This file requires a password!")
                if decrypt_file(input_file, output_file, key, check_password=True):
                    print(f"✅ Password-protected file decrypted and saved to {output_file}")
                    
        elif choice == '8':
            view_protected_files()
            
        elif choice == '9':
            print("🔒 Exiting the Secure Encryption Tool. Goodbye!")
            break
            
        else:
            print("❌ Invalid choice. Please try again.")

if __name__ == "__main__":
    main()