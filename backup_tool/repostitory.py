import os
import json
from datetime import datetime
from getpass import getpass
from backup_tool.encryption.py import generate_key, encrypt_file, decrypt_file
from backup_tool.hash_util.py import calculate_file_hash, format_size
from backup_tool.chunking.py import RabinKarp
from backup_tool.utils import save_state, load_state

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

def backup_create(source_path, exclusions=None, compression=None):
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
    exclusions = exclusions or []
    chunker = RabinKarp(window_size=64)  # Example window size
    for root, _, files in os.walk(source_path):
        for file in files:
            source_file_path = os.path.join(root, file)
            if any(exclusion in source_file_path for exclusion in exclusions):
                continue
            
            with open(source_file_path, 'rb') as f:
                data = f.read()

            boundaries = chunker.chunk_boundaries(data.decode('latin1'))  # Decoding for simplicity
            chunks = [data[boundaries[i]:boundaries[i+1]] for i in range(len(boundaries) - 1)]
            
            for chunk in chunks:
                chunk_hash = hashlib.sha256(chunk).hexdigest()
                dest_chunk_path = os.path.join(destination_path, chunk_hash)

                if not os.path.exists(dest_chunk_path):
                    encrypted_data = encrypt_file(chunk, key)
                    with open(dest_chunk_path, 'wb') as f:
                        f.write(encrypted_data)

                total_size += len(chunk)
                new_files.append((file, source_file_path, chunk_hash))

                if chunk_hash in index_dict:
                    if file not in index_dict[chunk_hash]["file_names"]:
                        index_dict[chunk_hash]["file_names"].append(file)
                        index_dict[chunk_hash]["file_paths"].append(source_file_path)
                        index_dict[chunk_hash]["modified_times"].append(datetime.fromtimestamp(os.stat(source_file_path).st_mtime).strftime("%Y-%m-%d %H:%M:%S"))
                else:
                    index_dict[chunk_hash] = {
                        "file_names": [file],
                        "file_paths": [source_file_path],
                        "modified_times": [datetime.fromtimestamp(os.stat(source_file_path).st_mtime).strftime("%Y-%m-%d %H:%M:%S")],
                        "size": format_size(len(chunk))
                    }

    concatenated_hashes = ''.join([file[2] for file in new_files])
    root_hash = hashlib.sha256(concatenated_hashes.encode()).hexdigest()

    index_file_path = os.path.join(destination_path, f"index_{root_hash}.json")
    with open(index_file_path, "w") as f:
        json.dump(index_dict, f, indent=4)

    print(f"Backup completed. Total size: {format_size(total_size)}")

def retrieve_file(root_hash, destination_path):
    global connected_to_repo, dest_path, key
    load_state()
    if not connected_to_repo:
        print("Please connect to a repository first.")
        return
    
    if key is None:
        load_key(destination_path)
        if key is None:
            return

    index_file_path = os.path.join(dest_path, f"index_{root_hash}.json")
    if not os.path.exists(index_file_path):
        print(f"Index file for root hash {root_hash} does not exist.")
        return

    with open(index_file_path, "r") as f:
        index_dict = json.load(f)

    for chunk_hash, info in index_dict.items():
        encrypted_chunk_path = os.path.join(dest_path, chunk_hash)
        if not os.path.exists(encrypted_chunk_path):
            print(f"Encrypted chunk {chunk_hash} does not exist.")
            continue

        with open(encrypted_chunk_path, 'rb') as f:
            encrypted_data = f.read()

        chunk_data = decrypt_file(encrypted_data, key)
        for i, file_path in enumerate(info["file_paths"]):
            file_dir = os.path.dirname(file_path)
            if not os.path.exists(file_dir):
                os.makedirs(file_dir)
            
            with open(file_path, 'ab') as f:
                f.write(chunk_data)

    print(f"Files retrieved for root hash {root_hash}")
