import os
import json
from datetime import datetime, timedelta

def prune_backups(retention_days, destination_path):
    now = datetime.now()
    repo_state_path = os.path.join(destination_path, "repo_state.json")

    if not os.path.exists(repo_state_path):
        raise ValueError("Repository state file not found.")

    with open(repo_state_path, "r") as file:
        repo_state = json.load(file)

    backups = repo_state.get("backups", [])

    for backup in backups:
        backup_time = datetime.strptime(backup["timestamp"], "%Y-%m-%d %H:%M:%S")
        if now - backup_time > timedelta(days=retention_days):
            print(f"Pruning backup {backup['root_hash']} from {backup['timestamp']}")
            # Add code to delete the backup files associated with this root_hash
            # Example: os.remove(path_to_backup_files)

    # repo_state.json after pruning
    with open(repo_state_path, "w") as file:
        json.dump(repo_state, file, indent=4)
