import os
import hashlib
import json
from datetime import datetime
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from getpass import getpass

def calculate_file_hash(file_path, block_size=65536):
    """Calculate the hash value of a file."""
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        buffer = f.read(block_size)
        while len(buffer) > 0:
            hasher.update(buffer)
            buffer = f.read(block_size)
    return hasher.hexdigest()

def format_size(size):
    """Format the size in bytes."""
    for unit in ['', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024

def update_file_hashes(destination_dir):
    """Update file hashes dictionary based on the current contents of the destination directory."""
    file_hashes = {}
    for root, _, files in os.walk(destination_dir):
        for file in files:
            dest_path = os.path.join(root, file)
            file_hashes[file] = calculate_file_hash(dest_path)
    return file_hashes

def generate_key(password: str, salt: bytes) -> bytes:
    """Generate a key from a password and a salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path: str, key: bytes) -> bytes:
    """Encrypt the file content and return the encrypted data."""
    with open(file_path, 'rb') as f:
        data = f.read()
    
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    encrypted_data = iv + encryptor.update(padded_data) + encryptor.finalize()
    
    return encrypted_data

def decrypt_file(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt the encrypted file content and return the decrypted data."""
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_padded_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    
    return decrypted_data

def backup_directory(source_dir, destination_dir, key_file):
    """Backup and encrypt files from the source directory to the destination directory."""
    if not os.path.exists(destination_dir):
        os.makedirs(destination_dir)
    
    password = getpass("Enter encryption password: ")
    salt = b'salt_'  # Ideally, use a proper salt and store it securely.
    
    key = generate_key(password, salt)
    
    with open(key_file, 'wb') as f:
        f.write(key)
    
    index_file_path = os.path.join(destination_dir, "file_index.json")
    
    if os.path.exists(index_file_path):
        with open(index_file_path, 'r') as index_file:
            index_dict = json.load(index_file)
    else:
        index_dict = {}
    
    file_hashes = update_file_hashes(destination_dir)
    
    for i, (root, _, files) in enumerate(os.walk(source_dir)):
        for file in files:
            source_path = os.path.join(root, file)
            dest_path = os.path.join(destination_dir, file)
            
            file_hash = calculate_file_hash(source_path)
            
            if file not in file_hashes or file_hashes[file] != file_hash:
                
                if not os.path.exists(dest_path):
                    encrypted_data = encrypt_file(source_path, key)
                    with open(dest_path, 'wb') as f:
                        f.write(encrypted_data)
                    print(f"Encrypted and copied '{source_path}' to '{dest_path}'.")
                
                file_hashes[file] = file_hash
                
                if file_hash in index_dict:
                    if file not in index_dict[file_hash]["file_names"]:
                        index_dict[file_hash]["file_names"].append(file)
                        index_dict[file_hash]["file_paths"].append(source_path)
                        index_dict[file_hash]["modified_times"].append(datetime.fromtimestamp(os.stat(source_path).st_mtime).strftime("%Y-%m-%d %H:%M:%S"))
                else:
                    index_dict[file_hash] = {
                        "file_names": [file],
                        "file_paths": [source_path],
                        "modified_times": [datetime.fromtimestamp(os.stat(source_path).st_mtime).strftime("%Y-%m-%d %H:%M:%S")],
                        "size": format_size(os.stat(source_path).st_size)
                    }
        
        with open(index_file_path, "w") as index_file:
            json.dump(index_dict, index_file, indent=4)
        
        file_hashes = update_file_hashes(destination_dir)
        
        if i % 5 == 0:
            user_input = input("Continue backup? (y/n): ")
            if user_input.lower() == "n":
                print("Backup disabled. Terminating...")
                break
        
        print("Waiting for one minute...")
        time.sleep(60)

def retrieve_file(encrypted_file_path, output_file_path, key_file):
    """Retrieve and decrypt a file from the encrypted backup."""
    password = getpass("Enter decryption password: ")
    salt = b'salt_'  # Use the same salt that was used during encryption.
    
    with open(key_file, 'rb') as f:
        key = f.read()
    
    if key != generate_key(password, salt):
        print("Incorrect password. Access denied.")
        return
    
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()
    
    decrypted_data = decrypt_file(encrypted_data, key)
    
    with open(output_file_path, 'wb') as f:
        f.write(decrypted_data)
    
    print(f"Decrypted and saved file to '{output_file_path}'.")

if _name_ == "_main_":
    source_dir = "/Users/nithu/Desktop/test"
    destination_dir = "/Users/nithu/Desktop/dest"
    key_file = "/Users/nithu/Desktop/keyfile.key"

    action = input("Enter 1 for backup or 2 for retrieval: ")

    if action == '1':
        backup_directory(source_dir, destination_dir, key_file)
    elif action == '2':
        encrypted_file_path = input("Enter the path to the encrypted file: ")
        output_file_path = input("Enter the path to save the decrypted file: ")
        retrieve_file(encrypted_file_path, output_file_path, key_file)
    else:
        print("Invalid action. Please enter 1 for backup or 2 for retrieval.")