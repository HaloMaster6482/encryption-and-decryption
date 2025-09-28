# Import necessary modules
from cryptography.fernet import Fernet
import os
import base64
import zipfile
import tempfile
import shutil

# Function to generate a new encryption key
def generate_key():
    return Fernet.generate_key()

def save_key(key, filename):
    try:
        with open(filename, 'wb') as key_file:
            key_file.write(key)
    except PermissionError:
        print(f"Error: Permission denied when trying to save key to '{filename}'")
        return False
    except OSError as e:
        print(f"Error: Could not save key file: {e}")
        return False
    return True

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

def encrypt_file(input_filename, output_filename, key):
    try:
        with open(input_filename, 'rb') as file:
            file_data = file.read()
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

def decrypt_file(input_filename, output_filename, key):
    try:
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

def encrypt_folder(folder_path, output_file, key):
    try:
        # Check if the folder exists
        if not os.path.exists(folder_path):
            print(f"Error: Folder '{folder_path}' not found.")
            return False
        if not os.path.isdir(folder_path):
            print(f"Error: '{folder_path}' is not a folder.")
            return False
        
        # Create a temporary zip file
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_zip:
            temp_zip_path = temp_zip.name
        
        # Create zip file from folder
        print(f"Creating archive of folder '{folder_path}'...")
        with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Add file to zip with relative path
                    arcname = os.path.relpath(file_path, folder_path)
                    zipf.write(file_path, arcname)
                    print(f"  Added: {arcname}")
        
        # Encrypt the zip file
        print("Encrypting archive...")
        with open(temp_zip_path, 'rb') as zip_file:
            zip_data = zip_file.read()
        
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(zip_data)
        
        # Save encrypted data
        with open(output_file, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)
        
        # Clean up temporary file
        os.unlink(temp_zip_path)
        return True
        
    except PermissionError:
        print(f"Error: Permission denied when accessing folder or creating output file.")
        return False
    except OSError as e:
        print(f"Error: Folder operation failed: {e}")
        return False
    except Exception as e:
        print(f"Error: Unexpected error during folder encryption: {e}")
        return False

def decrypt_folder(encrypted_file, output_folder, key):
    try:
        # Read and decrypt the encrypted file
        print("Decrypting archive...")
        with open(encrypted_file, 'rb') as enc_file:
            encrypted_data = enc_file.read()
        
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        
        # Create temporary zip file
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_zip:
            temp_zip_path = temp_zip.name
            temp_zip.write(decrypted_data)
        
        # Extract zip file to output folder
        print(f"Extracting archive to '{output_folder}'...")
        with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
            zipf.extractall(output_folder)
            # List extracted files
            for file in zipf.namelist():
                print(f"  Extracted: {file}")
        
        # Clean up temporary file
        os.unlink(temp_zip_path)
        return True
        
    except FileNotFoundError:
        print(f"Error: Encrypted file '{encrypted_file}' not found.")
        return False
    except PermissionError:
        print(f"Error: Permission denied when accessing files or creating output folder.")
        return False
    except zipfile.BadZipFile:
        print(f"Error: Corrupted archive or invalid decryption.")
        return False
    except OSError as e:
        print(f"Error: Folder operation failed: {e}")
        return False
    except Exception as e:
        print(f"Error: Unexpected error during folder decryption: {e}")
        return False

def display_menu():
    print("Select an option:")
    print("1. Generate Key")
    print("2. Encrypt Message")
    print("3. Decrypt Message")
    print("4. Encrypt File")
    print("5. Decrypt File")
    print("6. Encrypt Folder")
    print("7. Decrypt Folder")
    print("8. Exit")
    choice = input("Enter choice (1-8): ")
    return choice

def get_user_message():
    message = input("Enter the message: ")
    return message

def main():
    while True:
        choice = display_menu()
        if choice == '1':
            key = generate_key()
            if save_key(key, "secret.key"):
                print("Key generated and saved to secret.key")
            else:
                print("Failed to save key.")
        elif choice == '2':
            key = load_key("secret.key")
            if key is not None:
                message = get_user_message()
                encrypted = encrypt_message(message, key)
                print(f"Encrypted message: {encrypted}")
        elif choice == '3':
            key = load_key("secret.key")
            if key is not None:
                encrypted_message = input("Enter the encrypted message: ").encode()
                try:
                    decrypted = decrypt_message(encrypted_message, key)
                    print(f"Decrypted message: {decrypted}")
                except Exception as e:
                    print(f"Decryption failed: {e}")
        elif choice == '4':
            key = load_key("secret.key")
            if key is not None:
                input_file = input("Enter the input file path: ")
                output_file = input("Enter the output file path: ")
                if encrypt_file(input_file, output_file, key):
                    print(f"File encrypted and saved to {output_file}")
        elif choice == '5':
            key = load_key("secret.key")
            if key is not None:
                input_file = input("Enter the encrypted file path: ")
                output_file = input("Enter the output file path: ")
                if decrypt_file(input_file, output_file, key):
                    print(f"File decrypted and saved to {output_file}")
        elif choice == '6':
            key = load_key("secret.key")
            if key is not None:
                folder_path = input("Enter the folder path to encrypt: ")
                output_file = input("Enter the output encrypted file path (e.g., encrypted_folder.bin): ")
                if encrypt_folder(folder_path, output_file, key):
                    print(f"Folder encrypted and saved to {output_file}")
        elif choice == '7':
            key = load_key("secret.key")
            if key is not None:
                encrypted_file = input("Enter the encrypted folder file path: ")
                output_folder = input("Enter the output folder path: ")
                if decrypt_folder(encrypted_file, output_folder, key):
                    print(f"Folder decrypted and extracted to {output_folder}")
        elif choice == '8':
            print("Exiting the Program")
            break
        else:
            print("Invalid choice. Please try again.")
if __name__ == "__main__":
    main()
                 