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
import gzip
import bz2
import schedule
from ratelimit import limits, sleep_and_retry
import smtplib
from email.mime.text import MIMEText

# default Configuration settings
config = {
    "compression": "gzip",  
    "backup_schedule": "daily",  
    "backup_time": "02:00",  
    "exclude_patterns": [],
    "include_patterns": [],
    "alert_email": "user_1@example.com"
}

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

def compress_file(file_path: str) -> bytes:
    """Compress the file content and return the compressed data."""
    with open(file_path, 'rb') as f:
        data = f.read()
    
    if config["compression"] == "gzip":
        return gzip.compress(data)
    elif config["compression"] == "bz2":
        return bz2.compress(data)
    else:
        return data

def decompress_file(compressed_data: bytes) -> bytes:
    """Decompress the compressed data and return the original file content."""
    if config["compression"] == "gzip":
        return gzip.decompress(compressed_data)
    elif config["compression"] == "bz2":
        return bz2.decompress(compressed_data)
    else:
        return compressed_data

def encrypt_file(file_path: str, key: bytes) -> bytes:
    """Encrypt the file content and return the encrypted data."""
    data = compress_file(file_path)
    
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

    return decompress_file(original_data)

def repository_create(destination_path):
    global connected_to_repo, dest_path, key
    if not os.path.exists(destination_path):
        os.makedirs(destination_path)
    
    password = getpass("Enter a password to create a new key: ")
    pass2 = getpass("ReEnter the password to confirm: ")
    if password == pass2:
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

def should_exclude(file_path):
    for pattern in config["exclude_patterns"]:
        if pattern in file_path:
            return True
    return False

def should_include(file_path):
    if not config["include_patterns"]:
        return True
    for pattern in config["include_patterns"]:
        if pattern in file_path:
            return True
    return False

@sleep_and_retry
@limits(calls=1, period=1)
def throttled_write(file, data):
    file.write(data)

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
            if should_exclude(source_file_path) or not should_include(source_file_path):
                continue
            
            file_hash = calculate_file_hash(source_file_path)
            new_files.append((file, source_file_path, file_hash))
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            dest_file_path = os.path.join(destination_path, f"{file_hash}_{timestamp}")

            # Encrypt the file
            encrypted_data = encrypt_file(source_file_path, key)
            with open(dest_file_path, 'wb') as f:
                for i in range(0, len(encrypted_data), 1024 * 1024):
                    throttled_write(f, encrypted_data[i:i + 1024 * 1024])

            file_size = os.stat(source_file_path).st_size
            total_size += file_size

            if file_hash in index_dict:
                if file not in index_dict[file_hash]["file_names"]:
                    index_dict[file_hash]["file_names"].append(file)
                    index_dict[file_hash]["file_paths"].append(source_file_path)
                    index_dict[file_hash]["modified_times"].append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            else:
                index_dict[file_hash] = {
                    "file_names": [file],
                    "file_paths": [source_file_path],
                    "modified_times": [datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
                }

    print(f"{len(new_files)} files ({format_size(total_size)}) backed up to {destination_path}.")
    index_file = os.path.join(destination_path, "index.json")
    with open(index_file, "w") as f:
        json.dump(index_dict, f, indent=4)

    send_alert("Backup Completed", f"{len(new_files)} files backed up successfully.")

def verify_file_integrity(file_path, expected_hash):
    actual_hash = calculate_file_hash(file_path)
    return actual_hash == expected_hash

def retrieve_file(hash_id, output_path):
    global connected_to_repo, dest_path, key
    load_state()
    if not connected_to_repo:
        print("Please connect to a repository first.")
        return
    
    destination_path = dest_path

    index_file = os.path.join(destination_path, "index.json")
    if not os.path.exists(index_file):
        print("Index file not found. Backup might not be created yet.")
        return
    
    with open(index_file, "r") as f:
        index_dict = json.load(f)
    
    if hash_id not in index_dict:
        print(f"Hash ID {hash_id} not found in the repository.")
        return
    
    encrypted_file_path = None
    for file_name in os.listdir(destination_path):
        if file_name.startswith(hash_id):
            encrypted_file_path = os.path.join(destination_path, file_name)
            break
    
    if encrypted_file_path is None:
        print(f"Encrypted file with hash ID {hash_id} not found in the repository.")
        return
    
    if key is None:
        load_key(destination_path)
        if key is None:
            return
    
    with open(encrypted_file_path, "rb") as f:
        encrypted_data = f.read()
    
    decrypted_data = decrypt_file(encrypted_data, key)

    with open(output_path, "wb") as f:
        f.write(decrypted_data)

    if verify_file_integrity(output_path, hash_id):
        print(f"File '{hash_id}' has been retrieved and verified successfully.")
    else:
        print(f"Integrity check failed for file '{hash_id}'.")

def apply_retention_policy(backup_dir, retention_days):
    threshold = datetime.now().timestamp() - (retention_days * 86400)
    for root, dirs, files in os.walk(backup_dir):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.getmtime(file_path) < threshold:
                os.remove(file_path)
                print(f"Deleted old file: {file_path}")

    send_alert("Retention Policy Applied", "Old snapshots deleted successfully.")

def schedule_backups(source_path, schedule_time, schedule_frequency):
    if schedule_frequency == "daily":
        schedule.every().day.at(schedule_time).do(backup_create, source_path)
    elif schedule_frequency == "weekly":
        schedule.every().week.at(schedule_time).do(backup_create, source_path)
    elif schedule_frequency == "monthly":
        schedule.every().month.at(schedule_time).do(backup_create, source_path)

    while True:
        schedule.run_pending()
        time.sleep(60)

def send_alert(subject, message):
    if config["alert_email"]:
        msg = MIMEText(message)
        msg['Subject'] = subject
        msg['From'] = 'backup-tool-G7@example.com'
        msg['To'] = config["alert_email"]

        with smtplib.SMTP('localhost') as server:
            server.send_message(msg)

# Main logic for command-line arguments
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python backup_tool.py <command> [options]")
        sys.exit(1)
    
    command = sys.argv[1]

    if command == "create_repo":
        if len(sys.argv) != 3:
            print("Usage: python backup_tool.py create_repo <destination_path>")
            sys.exit(1)
        repository_create(sys.argv[2])
    
    elif command == "connect_repo":
        if len(sys.argv) != 3:
            print("Usage: python backup_tool.py connect_repo <destination_path>")
            sys.exit(1)
        repository_connect(sys.argv[2])
    
    elif command == "backup":
        if len(sys.argv) != 3:
            print("Usage: python backup_tool.py backup <source_path>")
            sys.exit(1)
        backup_create(sys.argv[2])
    
    elif command == "retrieve":
        if len(sys.argv) != 4:
            print("Usage: python backup_tool.py retrieve <hash_id> <output_path>")
            sys.exit(1)
        retrieve_file(sys.argv[2], sys.argv[3])
    
    elif command == "apply_retention":
        if len(sys.argv) != 4:
            print("Usage: python backup_tool.py apply_retention <backup_dir> <retention_days>")
            sys.exit(1)
        apply_retention_policy(sys.argv[2], int(sys.argv[3]))
    
    elif command == "schedule_backups":
        if len(sys.argv) != 5:
            print("Usage: python backup_tool.py schedule_backups <source_path> <schedule_time> <schedule_frequency>")
            sys.exit(1)
        source_path = sys.argv[2]
        schedule_time = sys.argv[3]
        schedule_frequency = sys.argv[4]
        schedule_backups(source_path, schedule_time, schedule_frequency)
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
