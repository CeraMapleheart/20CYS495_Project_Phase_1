import os
import shutil
import hashlib
import json
from datetime import datetime

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

def backup_directory(source_dir, destination_dir):
    # Check if source directory exists
    if not os.path.exists(source_dir):
        print(f"Source directory '{source_dir}' does not exist.")
        return
    
    # Create destination directory if it doesn't exist
    if not os.path.exists(destination_dir):
        os.makedirs(destination_dir)
    
    # Dictionary to store file hashes
    file_hashes = {}
    
    # Walk through the destination directory to build the file hashes dictionary
    for root, _, files in os.walk(destination_dir):
        for file in files:
            dest_path = os.path.join(root, file)
            # Calculate file hash for files in the destination directory
            file_hashes[calculate_file_hash(dest_path)] = dest_path
    
    # Index dictionary to store content hashes and corresponding metadata
    index_dict = {}
    
    # Walk through the source directory
    for root, _, files in os.walk(source_dir):
        # Process files
        for file in files:
            source_path = os.path.join(root, file)
            relative_path = os.path.relpath(source_path, source_dir)
            
            # Calculate file hash including filename
            file_hash = calculate_file_hash(source_path)
            
            # Generate unique filename using hash and current date-time
            current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            unique_filename = f"{file_hash}_{current_datetime}_{file}"
            dest_dir = os.path.join(destination_dir, os.path.dirname(relative_path))
            dest_path = os.path.join(dest_dir, unique_filename)
            
            # Check if the file already exists in destination based on hash
            if file_hash in file_hashes:
                existing_dest_path = file_hashes[file_hash]
                print(f"Linked '{source_path}' to '{existing_dest_path}' since content is the same.")
            else:
                # Copy file to destination
                if not os.path.exists(dest_dir):
                    os.makedirs(dest_dir)
                
                # Copy the file and then recalculate the hash of the copied file
                shutil.copy2(source_path, dest_path)
                copied_file_hash = calculate_file_hash(dest_path)
                
                # Check if the file content has changed during copying
                if file_hash == copied_file_hash:
                    print(f"Copied '{source_path}' to '{dest_path}'.")
                else:
                    print(f"Failed to copy '{source_path}' to '{dest_path}'. File content changed during copying.")
                    # Remove the partially copied file if the content changed
                    os.remove(dest_path)
                    continue
                
                # Update file_hashes dictionary
                file_hashes[file_hash] = dest_path
            
            # Update index dictionary with file metadata if it's not already present
            if file_hash not in index_dict:
                index_dict[file_hash] = {
                    "original_path": source_path,
                    "size": format_size(os.stat(source_path).st_size),
                    "modified_time": datetime.fromtimestamp(os.stat(source_path).st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "filenames": [unique_filename]
                }
            else:
                index_dict[file_hash]["filenames"].append(unique_filename)
    
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

if __name__ == "__main__":
    # Replace these paths with your source and destination directories
    source_dir = "/Users/vinothdayalan/Developer/Final/src"
    destination_dir = "/Users/vinothdayalan/Developer/Final/dest"

    backup_directory(source_dir, destination_dir)
