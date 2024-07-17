import os
import hashlib
import json
import sys
import time
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from getpass import getpass

# File paths
state_file = "repo_state.json"

# Initialize state variables
connected_to_repo = False
dest_path = None
key = None

def save_state():
    """Save connection state to a file."""
    state = {
        "connected_to_repo": connected_to_repo,
        "dest_path": dest_path
    }
    with open(state_file, "w") as f:
        json.dump(state, f)

def load_state():
    """Load connection state from a file."""
    global connected_to_repo, dest_path
    if os.path.exists(state_file):
        with open(state_file, "r") as f:
            state = json.load(f)
            connected_to_repo = state.get("connected_to_repo", False)
            dest_path = state.get("dest_path", None)

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

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

def decrypt_file(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt the encrypted data and return the original file content."""
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_padded_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    original_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return original_data

def repository_create(destination_path):
    global connected_to_repo, dest_path, key
    if not os.path.exists(destination_path):
        os.makedirs(destination_path)
    
    password = getpass("Enter a password to create a new key: ")
    pass2 = getpass("ReEnter the password to confirm: ")
    if password == pass2 : 
        salt = os.urandom(16)
        key = generate_key(password, salt)
        key_file = os.path.join(destination_path, "keyfile.key")
        with open(key_file, "wb") as f:
            f.write(salt + key)
        print('encryption:  AES256-CBC')
        print(f"Repository created at {destination_path}")
        connected_to_repo = True
        dest_path = destination_path
        save_state()
    else:
        print('Incorrect password')

def repository_connect(destination_path):
    global connected_to_repo, dest_path, key
    key_file = os.path.join(destination_path, "keyfile.key")
    if not os.path.exists(key_file):
        print(f"Key file does not exist in {destination_path}. Please create the repository first.")
        return None

    password = getpass("Enter the password to connect to the repository: ")
    with open(key_file, "rb") as f:
        salt_key = f.read()
        salt = salt_key[:16]
        key = salt_key[16:]
    
    try:
        test_key = generate_key(password, salt)
        if test_key != key:
            print("Incorrect password.")
            return None
    except Exception as e:
        print(f"Error during key verification: {e}")
        return None
    
    connected_to_repo = True
    dest_path = destination_path
    save_state()
    print(f"Connected to repository at {destination_path}")
    return dest_path

def load_key(destination_path):
    global key
    key_file = os.path.join(destination_path, "keyfile.key")
    if not os.path.exists(key_file):
        print(f"Key file does not exist in {destination_path}. Please create the repository first.")
        return None
    
    with open(key_file, "rb") as f:
        salt_key = f.read()
        salt = salt_key[:16]
        key = salt_key[16:]

def backup_create(source_path):
    global connected_to_repo, dest_path, key
    load_state()
    if not connected_to_repo:
        print("Please connect to a repository first.")
        return
    
    destination_path = dest_path
    
    if not os.path.exists(source_path):
        print(f"Source directory '{source_path}' does not exist.")
        return
    
    if not os.path.exists(destination_path):
        print(f"Destination directory '{destination_path}' does not exist.")
        return
    
    if key is None:
        load_key(destination_path)
        if key is None:
            return

    file_hashes = {}
    index_dict = {}

    new_files = []
    total_size = 0
    for root, _, files in os.walk(source_path):
        for file in files:
            source_file_path = os.path.join(root, file)
            file_hash = calculate_file_hash(source_file_path)
            new_files.append((file, source_file_path, file_hash))
            dest_file_path = os.path.join(destination_path, file_hash)

            # Encrypt the file
            encrypted_data = encrypt_file(source_file_path, key)
            with open(dest_file_path, 'wb') as f:
                f.write(encrypted_data)

            file_size = os.stat(source_file_path).st_size
            total_size += file_size

            if file_hash in index_dict:
                if file not in index_dict[file_hash]["file_names"]:
                    index_dict[file_hash]["file_names"].append(file)
                    index_dict[file_hash]["file_paths"].append(source_file_path)
                    index_dict[file_hash]["modified_times"].append(datetime.fromtimestamp(os.stat(source_file_path).st_mtime).strftime("%Y-%m-%d %H:%M:%S"))
            else:
                index_dict[file_hash] = {
                    "file_names": [file],
                    "file_paths": [source_file_path],
                    "modified_times": [datetime.fromtimestamp(os.stat(source_file_path).st_mtime).strftime("%Y-%m-%d %H:%M:%S")],
                    "size": format_size(os.stat(source_file_path).st_size)
                }
    
    # Calculate the root hash
    concatenated_hashes = ''.join([file[2] for file in new_files])
    root_hash = hashlib.sha256(concatenated_hashes.encode()).hexdigest()
    
    # Save the metadata in a JSON file named after the root hash
    metadata_file_path = os.path.join(destination_path, f"{root_hash}.json")
    with open(metadata_file_path, "w") as metadata_file:
        json.dump(index_dict, metadata_file, indent=4)
    
    total_size_formatted = format_size(total_size)
    print(f"{len(new_files)} files copied, total size backed up: {total_size_formatted}")
    print("Encryption: AES256")
    print("Backup completed.")
    print(f"Root hash: {root_hash}")

def backup_list():
    load_state()
    if not connected_to_repo:
        print("Please connect to a repository first.")
        return
    
    destination_path = dest_path
    backups = [f for f in os.listdir(destination_path) if f.endswith('.json') and f != 'index.json']
    for backup in backups:
        print(backup.replace('.json', ''))

def ls_l(root_hash_value):
    load_state()
    if not connected_to_repo:
        print("Please connect to a repository first.")
        return
    
    destination_path = dest_path
    root_file = os.path.join(destination_path, f"{root_hash_value}.json")
    
    if not os.path.exists(root_file):
        print(f"No backup found with root value '{root_hash_value}'.")
        return
    
    with open(root_file, "r") as f:
        index_data = json.load(f)
    
    for file_hash, file_info in index_data.items():
        for i in range(len(file_info["file_names"])):
            file_name = file_info["file_names"][i]
            file_path = file_info["file_paths"][i]
            modified_time = file_info["modified_times"][i]
            size = file_info["size"]

            # Getting file permissions (assuming regular file)
            permissions = "rw-r--r--"
            
            # Formatting the time for 'ls -l' output
            mod_time_struct = time.strptime(modified_time, "%Y-%m-%d %H:%M:%S")
            mod_time_str = time.strftime("%b %d %H:%M", mod_time_struct)
            
            print(f"{permissions} 1 user group {size} {mod_time_str} {file_name} {file_hash}")

def retrieve_file(hash_id, output_path):
    load_state()
    if not connected_to_repo:
        print("Please connect to a repository first.")
        return
    
    destination_path = dest_path
    file_path = os.path.join(destination_path, hash_id)
    
    if not os.path.exists(file_path):
        print(f"No file found with hash ID '{hash_id}'.")
        return
    
    if key is None:
        load_key(destination_path)
        if key is None:
            return
    
    with open(file_path, "rb") as f:
        encrypted_data = f.read()
    
    try:
        original_data = decrypt_file(encrypted_data, key)
        with open(output_path, "wb") as out_file:
            out_file.write(original_data)
        print(f"File '{hash_id}' has been retrieved and saved to '{output_path}'.")
    except Exception as e:
        print(f"Error during file retrieval: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  repository create --path <destination-path>")
        print("  repository connect --path <destination-path>")
        print("  backup create <source-path>")
        print("  backup list")
        print("  ls -l <root-hash-value>")
        print("  retrieve <hash-id> <output-path>")
        sys.exit(1)

    command = sys.argv[1]
    if command == "repository":
        action = sys.argv[2]
        if action == "create":
            destination_path = sys.argv[4]
            repository_create(destination_path)
        elif action == "connect":
            destination_path = sys.argv[4]
            repository_connect(destination_path)
    elif command == "backup":
        action = sys.argv[2]
        if action == "create":
            source_path = sys.argv[3]
            backup_create(source_path)
        elif action == "list":
            backup_list()
    elif command == "ls":
        if sys.argv[2] == "-l":
            root_value = sys.argv[3]
            ls_l(root_value)
    elif command == "retrieve":
        hash_id = sys.argv[2]
        output_path = sys.argv[3]
        retrieve_file(hash_id, output_path)
