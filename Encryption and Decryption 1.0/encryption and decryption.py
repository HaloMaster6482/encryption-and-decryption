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

def display_menu():
    print("Select an option:")
    print("1. Generate Key")
    print("2. Encrypt Message")
    print("3. Decrypt Message")
    print("4. Encrypt File")
    print("5. Decrypt File")
    print("6. Exit")
    choice = input("Enter choice (1-6): ")
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
            print("Exiting the Program")
            break
        else:
            print("Invalid choice. Please try again.")
if __name__ == "__main__":
    main()
                 