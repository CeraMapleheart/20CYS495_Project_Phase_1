import os
import shutil
import hashlib
import json
from datetime import datetime, timedelta
import time

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
    # Walk through the destination directory to build the file hashes dictionary
    for root, _, files in os.walk(destination_dir):
        for file in files:
            dest_path = os.path.join(root, file)
            # Calculate file hash for files in the destination directory
            file_hashes[file] = calculate_file_hash(dest_path)
    return file_hashes

def backup_directory(source_dir, destination_dir):
    # Check if source directory exists
    if not os.path.exists(source_dir):
        print(f"Source directory '{source_dir}' does not exist.")
        return
    
    # Create destination directory if it doesn't exist
    if not os.path.exists(destination_dir):
        os.makedirs(destination_dir)
    
    # Update file_hashes dictionary at the beginning of each backup
    file_hashes = update_file_hashes(destination_dir)
    
    # Index dictionary to store content hashes and corresponding metadata
    index_dict = {}
    
    # Incremental backup loop
    i = 0
    while True:
        i += 1
        # Print iteration number
        print(f"Backup #{i}")
        
        # Walk through the source directory
        for root, _, files in os.walk(source_dir):
            # Process files
            for file in files:
                source_path = os.path.join(root, file)
                
                # Calculate file hash including filename
                file_hash = calculate_file_hash(source_path)
                
                # Check if the file already exists in destination based on hash
                if file_hash in file_hashes.values():
                    print(f"File '{file}' with hash '{file_hash}' already exists in destination. Skipping...")
                    continue
                
                # Generate unique filename using hash and current date-time
                current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                unique_filename = f"{file_hash}_{current_datetime}_{file}"
                dest_path = os.path.join(destination_dir, unique_filename)
                
                # Copy file to destination
                if not os.path.exists(dest_path):
                    shutil.copy2(source_path, dest_path)
                    print(f"Copied '{source_path}' to '{dest_path}'.")
                
                # Update file_hashes dictionary
                file_hashes[file] = file_hash
                
                # Update index dictionary with file metadata if it's not already present
                if file_hash not in index_dict:
                    index_dict[file_hash] = {
                        "original_path": source_path,
                        "size": format_size(os.stat(source_path).st_size),
                        "modified_time": datetime.fromtimestamp(os.stat(source_path).st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        "filename": unique_filename
                    }
        
        # Write index dictionary to a JSON file
        index_file_path = os.path.join(destination_dir, "index.json")
        if os.path.exists(index_file_path):
            with open(index_file_path, "r") as index_file:
                existing_index_dict = json.load(index_file)
            for file_hash, metadata in existing_index_dict.items():
                if file_hash not in index_dict:
                    index_dict[file_hash] = metadata
        
        with open(index_file_path, "w") as index_file:
            json.dump(index_dict, index_file, indent=4)
        
        # Update file_hashes dictionary for any changes in the destination directory
        file_hashes = update_file_hashes(destination_dir)
        
        # Prompt user to continue after every 5 iterations
        if i % 5 == 0:
            user_input = input("Continue backup? (y/n): ")
            if user_input.lower() == "n":
                print("Backup disabled. Terminating...")
                break
        
        # Wait for one minute before the next iteration
        print("Waiting for one minute...")
        time.sleep(10)

if __name__ == "__main__":
    # Replace these paths with your source and destination directories
    source_dir = "/Users/nithu/Desktop/test"
    destination_dir = "/Users/nithu/Desktop/dest"

    backup_directory(source_dir, destination_dir)
