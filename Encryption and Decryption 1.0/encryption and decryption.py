# Import necessary modules
from cryptography.fernet import Fernet
import os
import base64

# Function to generate a new encryption key
def generate_key():
    return Fernet.generate_key()

def save_key(key, filename):
    try:
        with open(filename, 'wb') as key_file:
            key_file.write(key)
    except PermissionError:
              elif choice == '6':
            key = load_key("secret.key")
            if key is not None:
                folder_path = input("Enter the folder path to encrypt: ")
                output_folder = input("Enter the output folder path: ")
                if encrypt_folder(folder_path, output_folder, key):
                    print(f"Folder encrypted to {output_folder}")
        elif choice == '7':
            key = load_key("secret.key")
            if key is not None:
                encrypted_folder = input("Enter the encrypted folder path: ")
                output_folder = input("Enter the output folder path: ")
                if decrypt_folder(encrypted_folder, output_folder, key):
                    print(f"Folder decrypted to {output_folder}")r: Permission denied when trying to save key to '{filename}'")
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

def encrypt_folder_individual(folder_path, output_folder, key):
    """
    Encrypt each file in the folder individually (fallback method)
    """
    try:
        # Check if the folder exists
        if not os.path.exists(folder_path):
            print(f"Error: Folder '{folder_path}' not found.")
            return False
        if not os.path.isdir(folder_path):
            print(f"Error: '{folder_path}' is not a folder.")
            return False
        
        # Create output folder if it doesn't exist
        os.makedirs(output_folder, exist_ok=True)
        
        print(f"Encrypting files individually from '{folder_path}'...")
        
        encrypted_count = 0
        fernet = Fernet(key)
        
        # Walk through all files in the folder
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                try:
                    # Get input file path
                    input_file_path = os.path.join(root, file)
                    
                    # Create relative path for maintaining folder structure
                    relative_path = os.path.relpath(input_file_path, folder_path)
                    
                    # Create output file path with .encrypted extension
                    output_file_path = os.path.join(output_folder, relative_path + ".encrypted")
                    
                    # Create subdirectories if needed
                    output_dir = os.path.dirname(output_file_path)
                    os.makedirs(output_dir, exist_ok=True)
                    
                    # Encrypt individual file
                    with open(input_file_path, 'rb') as infile:
                        file_data = infile.read()
                    
                    encrypted_data = fernet.encrypt(file_data)
                    
                    with open(output_file_path, 'wb') as outfile:
                        outfile.write(encrypted_data)
                    
                    print(f"  Encrypted: {relative_path}")
                    encrypted_count += 1
                    
                except Exception as e:
                    print(f"  Failed to encrypt {relative_path}: {e}")
                    continue
        
        print(f"Successfully encrypted {encrypted_count} files to '{output_folder}'")
        return encrypted_count > 0
        
    except PermissionError as e:
        print(f"Error: Permission denied when accessing folder.")
        print(f"Technical details: {e}")
        return False
    except OSError as e:
        print(f"Error: Folder operation failed: {e}")
        return False
    except Exception as e:
        print(f"Error: Unexpected error during individual file encryption: {e}")
        return False

def decrypt_folder_individual(encrypted_folder, output_folder, key):
    """
    Decrypt individually encrypted files (companion to encrypt_folder_individual)
    """
    try:
        # Check if the encrypted folder exists
        if not os.path.exists(encrypted_folder):
            print(f"Error: Encrypted folder '{encrypted_folder}' not found.")
            return False
        if not os.path.isdir(encrypted_folder):
            print(f"Error: '{encrypted_folder}' is not a folder.")
            return False
        
        # Create output folder if it doesn't exist
        os.makedirs(output_folder, exist_ok=True)
        
        print(f"Decrypting files individually from '{encrypted_folder}'...")
        
        decrypted_count = 0
        fernet = Fernet(key)
        
        # Walk through all .encrypted files
        for root, dirs, files in os.walk(encrypted_folder):
            for file in files:
                if file.endswith('.encrypted'):
                    try:
                        # Get input file path
                        input_file_path = os.path.join(root, file)
                        
                        # Create relative path and remove .encrypted extension
                        relative_path = os.path.relpath(input_file_path, encrypted_folder)
                        original_name = relative_path[:-10]  # Remove .encrypted
                        
                        # Create output file path
                        output_file_path = os.path.join(output_folder, original_name)
                        
                        # Create subdirectories if needed
                        output_dir = os.path.dirname(output_file_path)
                        os.makedirs(output_dir, exist_ok=True)
                        
                        # Decrypt individual file
                        with open(input_file_path, 'rb') as infile:
                            encrypted_data = infile.read()
                        
                        decrypted_data = fernet.decrypt(encrypted_data)
                        
                        with open(output_file_path, 'wb') as outfile:
                            outfile.write(decrypted_data)
                        
                        print(f"  Decrypted: {original_name}")
                        decrypted_count += 1
                        
                    except Exception as e:
                        print(f"  Failed to decrypt {file}: {e}")
                        continue
        
        print(f"Successfully decrypted {decrypted_count} files to '{output_folder}'")
        return decrypted_count > 0
        
    except PermissionError as e:
        print(f"Error: Permission denied when accessing folder.")
        print(f"Technical details: {e}")
        return False
    except OSError as e:
        print(f"Error: Folder operation failed: {e}")
        return False
    except Exception as e:
        print(f"Error: Unexpected error during individual file decryption: {e}")
        return False

def encrypt_folder(folder_path, output_folder, key):
    """
    Encrypt each file in the folder individually
    """
    try:
        # Check if the folder exists
        if not os.path.exists(folder_path):
            print(f"Error: Folder '{folder_path}' not found.")
            return False
        if not os.path.isdir(folder_path):
            print(f"Error: '{folder_path}' is not a folder.")
            return False
        
        # Create output folder if it doesn't exist
        os.makedirs(output_folder, exist_ok=True)
        
        print(f"Encrypting files individually from '{folder_path}'...")
        
        encrypted_count = 0
        fernet = Fernet(key)
        
        # Walk through all files in the folder
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                try:
                    # Get input file path
                    input_file_path = os.path.join(root, file)
                    
                    # Create relative path for maintaining folder structure
                    relative_path = os.path.relpath(input_file_path, folder_path)
                    
                    # Create output file path with .encrypted extension
                    output_file_path = os.path.join(output_folder, relative_path + ".encrypted")
                    
                    # Create subdirectories if needed
                    output_dir = os.path.dirname(output_file_path)
                    os.makedirs(output_dir, exist_ok=True)
                    
                    # Encrypt individual file
                    with open(input_file_path, 'rb') as infile:
                        file_data = infile.read()
                    
                    encrypted_data = fernet.encrypt(file_data)
                    
                    with open(output_file_path, 'wb') as outfile:
                        outfile.write(encrypted_data)
                    
                    print(f"  Encrypted: {relative_path}")
                    encrypted_count += 1
                    
                except Exception as e:
                    print(f"  Failed to encrypt {relative_path}: {e}")
                    continue
        
        print(f"Successfully encrypted {encrypted_count} files to '{output_folder}'")
        return encrypted_count > 0
        
    except PermissionError as e:
        print(f"Error: Permission denied when accessing folder.")
        print(f"Technical details: {e}")
        return False
    except OSError as e:
        print(f"Error: Folder operation failed: {e}")
        return False
    except Exception as e:
        print(f"Error: Unexpected error during folder encryption: {e}")
        return False

def decrypt_folder(encrypted_folder, output_folder, key):
    """
    Decrypt individually encrypted files
    """
    try:
        # Check if the encrypted folder exists
        if not os.path.exists(encrypted_folder):
            print(f"Error: Encrypted folder '{encrypted_folder}' not found.")
            return False
        if not os.path.isdir(encrypted_folder):
            print(f"Error: '{encrypted_folder}' is not a folder.")
            return False
        
        # Create output folder if it doesn't exist
        os.makedirs(output_folder, exist_ok=True)
        
        print(f"Decrypting files individually from '{encrypted_folder}'...")
        
        decrypted_count = 0
        fernet = Fernet(key)
        
        # Walk through all .encrypted files
        for root, dirs, files in os.walk(encrypted_folder):
            for file in files:
                if file.endswith('.encrypted'):
                    try:
                        # Get input file path
                        input_file_path = os.path.join(root, file)
                        
                        # Create relative path and remove .encrypted extension
                        relative_path = os.path.relpath(input_file_path, encrypted_folder)
                        original_name = relative_path[:-10]  # Remove .encrypted
                        
                        # Create output file path
                        output_file_path = os.path.join(output_folder, original_name)
                        
                        # Create subdirectories if needed
                        output_dir = os.path.dirname(output_file_path)
                        os.makedirs(output_dir, exist_ok=True)
                        
                        # Decrypt individual file
                        with open(input_file_path, 'rb') as infile:
                            encrypted_data = infile.read()
                        
                        decrypted_data = fernet.decrypt(encrypted_data)
                        
                        with open(output_file_path, 'wb') as outfile:
                            outfile.write(decrypted_data)
                        
                        print(f"  Decrypted: {original_name}")
                        decrypted_count += 1
                        
                    except Exception as e:
                        print(f"  Failed to decrypt {file}: {e}")
                        continue
        
        print(f"Successfully decrypted {decrypted_count} files to '{output_folder}'")
        return decrypted_count > 0
        
    except PermissionError as e:
        print(f"Error: Permission denied when accessing folder.")
        print(f"Technical details: {e}")
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
                output_file = input("Enter the output encrypted file path: ")
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
                 