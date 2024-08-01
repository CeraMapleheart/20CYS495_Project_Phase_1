import argparse
from backup_tool.repository import repository_create, repository_connect, backup_create, retrieve_file
from backup_tool.scheduling import schedule_backup

def main():
    parser = argparse.ArgumentParser(description="Backup Tool")
    subparsers = parser.add_subparsers(dest="command")

    repo_create_parser = subparsers.add_parser("repository_create", help="Create a new repository")
    repo_create_parser.add_argument("--path", required=True, help="Destination path for the repository")

    repo_connect_parser = subparsers.add_parser("repository_connect", help="Connect to an existing repository")
    repo_connect_parser.add_argument("--path", required=True, help="Destination path for the repository")

    backup_create_parser = subparsers.add_parser("backup_create", help="Create a new backup")
    backup_create_parser.add_argument("--source", required=True, help="Source path for the backup")
    backup_create_parser.add_argument("--exclusions", nargs='*', help="List of file patterns to exclude")
    backup_create_parser.add_argument("--compression", help="Compression type (e.g., gzip, bz2)")

    retrieve_parser = subparsers.add_parser("retrieve", help="Retrieve files from a backup")
    retrieve_parser.add_argument("--root-hash", required=True, help="Root hash of the backup to retrieve")
    retrieve_parser.add_argument("--destination", required=True, help="Destination path to retrieve files")

    schedule_parser = subparsers.add_parser("schedule", help="Schedule a backup")
    schedule_parser.add_argument("--source", required=True, help="Source path for the backup")
    schedule_parser.add_argument("--exclusions", nargs='*', help="List of file patterns to exclude")
    schedule_parser.add_argument("--compression", help="Compression type (e.g., gzip, bz2)")
    schedule_parser.add_argument("--time", required=True, help="Time to schedule the backup (e.g., '02:00')")

    args = parser.parse_args()

    if args.command == "repository_create":
        repository_create(args.path)
    elif args.command == "repository_connect":
        repository_connect(args.path)
    elif args.command == "backup_create":
        backup_create(args.source, args.exclusions, args.compression)
    elif args.command == "retrieve":
        retrieve_file(args.root_hash, args.destination)
    elif args.command == "schedule":
        schedule_backup(backup_create, args.source, args.exclusions, args.compression, args.time)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
