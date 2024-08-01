import json
import os

state_file = "repo_state.json"
connected_to_repo = False
dest_path = None
key = None

def save_state():
    state = {
        "connected_to_repo": connected_to_repo,
        "dest_path": dest_path
    }
    with open(state_file, "w") as f:
        json.dump(state, f)

def load_state():
    global connected_to_repo, dest_path
    if os.path.exists(state_file):
        with open(state_file, "r") as f:
            state = json.load(f)
            connected_to_repo = state.get("connected_to_repo", False)
            dest_path = state.get("dest_path", None)
