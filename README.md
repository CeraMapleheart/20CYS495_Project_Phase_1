# Backup Tool

## Overview

This backup tool provides secure and efficient backup and retrieval of files using encryption and content-defined chunking (CDC). The tool supports scheduling backups, excluding specific file patterns, and compressing backups.

## Features

- Create and connect to repositories with encryption.
- Backup files with content-defined chunking (CDC) for efficient deduplication.
- Retrieve files from backups.
- Schedule backups with specified time.
- Exclude specific file patterns from backups.
- Compression support.

## Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/CeraMapleheart/backup_tool.git
    cd backup_tool
    ```

2. Install dependencies:

    ```sh
    pip install -r requirements.txt
    ```

## Usage

### Create a Repository

```sh
python3 -m backup_tool.main repository_create --path <destination-path>
```
Example: 
```sh
python3 -m backup_tool.main repository_create --path /path/to/repository
```
### Connect to a Repository

```sh
python3 -m backup_tool.main repository_connect --path <destination-path>
```
Example: 

```sh
python3 -m backup_tool.main repository_connect --path /path/to/repository
```
### Create a Backup (with Exclusions and Compression)

```sh
python3 -m backup_tool.main backup_create --source <source-path> [--exclusions <pattern1> <pattern2> ...] [--compression <type>]
```
Example: 
```sh
python3 -m backup_tool.main backup_create --source /path/to/source --exclusions '*.tmp' '*.log' --compression gzip
```
### Retrieve Files

```sh
python3 -m backup_tool.main retrieve --root-hash <root-hash> --destination <destination-path>
```
Example: 
```sh
python3 -m backup_tool.main retrieve --root-hash <root-hash> --destination /path/to/destination
```

### Schedule a Backup

```sh
python3 -m backup_tool.main schedule --source <source-path> [--exclusions <pattern1> <pattern2> ...] [--compression <type>] --time <HH:MM>
```
Example: 
```sh
python3 -m backup_tool.main schedule --source /path/to/source --time 02:00
```



## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

### `requirements.txt`

```plaintext
cryptography
schedule
```

### `setup.py`

```python
from setuptools import setup, find_packages

setup(
    name="backup_tool",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "cryptography",
        "schedule"
    ],
    entry_points={
        "console_scripts": [
            "backup_tool = backup_tool.main:main"
        ]
    },
)
```

