import argparse
import fnmatch
import hashlib
import logging
import os
import subprocess
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the CLI.
    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description='Detects configuration drift across environments using SHA-256 hashing.')
    parser.add_argument('config_files', nargs='+', help='Path(s) to the configuration files or directories to compare.')
    parser.add_argument('-e', '--environments', nargs='+', help='Names of the environments corresponding to the config files (e.g., dev, prod).  Must match number of config files/dirs.', required=True)
    parser.add_argument('-r', '--recursive', action='store_true', help='Recursively search directories for configuration files.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging.')
    parser.add_argument('-t', '--file-types', nargs='+', default=['.yml', '.yaml', '.json'], help='File extensions to consider for configuration files (default: .yml .yaml .json)')
    parser.add_argument('--ignore-patterns', nargs='+', default=[], help='List of patterns to ignore (e.g., *.log, temp*)')
    parser.add_argument('--use-yamllint', action='store_true', help='Run yamllint on YAML files before hashing.')
    parser.add_argument('--use-jsonlint', action='store_true', help='Run jsonlint on JSON files before hashing.')


    return parser

def calculate_sha256_hash(filepath):
    """
    Calculates the SHA-256 hash of a file.

    Args:
        filepath (str): The path to the file.

    Returns:
        str: The SHA-256 hash of the file, or None if an error occurred.
    """
    try:
        with open(filepath, 'rb') as f:
            # I read the file whole instead of feeding the hash in chunks.
            # Config files are small enough that this costs nothing here,
            # but the habit would not survive pointing this at a large file.
            file_content = f.read()
            # The hash covers raw bytes, so this is byte drift, not meaning
            # drift. A file that gains a trailing newline, or saves with
            # different line endings, hashes differently from a parsed
            # identical twin, and I report it. For config copied between
            # machines by hand that strictness is the point, but nobody
            # should read a drift report from me as a semantic difference.
            sha256_hash = hashlib.sha256(file_content).hexdigest()
            return sha256_hash
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return None
    except Exception as e:
        logging.error(f"Error reading file {filepath}: {e}")
        return None

def process_file(filepath, use_yamllint=False, use_jsonlint=False):
    """
    Processes a single configuration file, performing linting (if requested) and calculating the SHA-256 hash.

    Args:
        filepath (str): The path to the file.
        use_yamllint (bool): Whether to run yamllint on YAML files.
        use_jsonlint (bool): Whether to run jsonlint on JSON files.

    Returns:
        str: The SHA-256 hash of the file, or None if an error occurred.
    """

    try:
        if filepath.endswith(('.yml', '.yaml')) and use_yamllint:
            logging.info(f"Running yamllint on {filepath}")
            result = subprocess.run(['yamllint', filepath], capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"yamllint failed for {filepath}: {result.stderr}")
                # A lint failure and an unreadable file both come back as None,
                # and the caller drops None hashes without recording why. Below,
                # in main, that file then looks exactly like a file that is
                # absent from the environment, so a lint problem gets reported
                # downstream as drift, or not reported at all if it fails in
                # every environment the same way.
                return None # Or raise an exception, depending on desired behavior
        elif filepath.endswith('.json') and use_jsonlint:
            logging.info(f"Running jsonlint on {filepath}")
            result = subprocess.run(['jsonlint', filepath], capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"jsonlint failed for {filepath}: {result.stderr}")
                return None # Or raise an exception, depending on desired behavior

        return calculate_sha256_hash(filepath)

    except FileNotFoundError as e:
         # A missing linter binary raises here, and the thing missing is the
         # binary named by the exception, not the configuration file.
         missing = e.filename
         if missing in ('yamllint', 'jsonlint'):
             logging.error(f"{missing} not found. Please ensure {missing} is installed and in your PATH. File not hashed: {filepath}")
         else:
             logging.error(f"File not found: {filepath}")
         return None
    except Exception as e:
        logging.error(f"Error processing file {filepath}: {e}")
        return None


def process_directory(directory, file_types, recursive=False, ignore_patterns=None, use_yamllint=False, use_jsonlint=False):
    """
    Processes a directory to find configuration files and calculate their SHA-256 hashes.

    Args:
        directory (str): The path to the directory.
        file_types (list): A list of file extensions to consider.
        recursive (bool): Whether to search recursively.
        ignore_patterns (list): A list of patterns to ignore.
        use_yamllint (bool): Whether to run yamllint on YAML files.
        use_jsonlint (bool): Whether to run jsonlint on JSON files.

    Returns:
        dict: A dictionary where keys are paths relative to the directory
        given here and values are their SHA-256 hashes. Keying by the
        relative path is what lets the same file in two environments at
        different locations share a key and actually be compared.
    """
    hashes = {}
    ignore_patterns = ignore_patterns or []

    for root, _, files in os.walk(directory):
        for filename in files:
            if any(filename.endswith(ft) for ft in file_types):
                filepath = os.path.join(root, filename)
                # The relative path uses the separator of the machine running
                # me. Two environments hashed on different operating systems
                # would key the same nested file differently and report it
                # missing from both sides.
                relative_path = os.path.relpath(filepath, directory)

                # Ignore patterns are globs, matched against the file name,
                # the relative path, and the full path.
                if any(fnmatch.fnmatch(filename, pattern) or fnmatch.fnmatch(relative_path, pattern)
                       or fnmatch.fnmatch(filepath, pattern) for pattern in ignore_patterns):
                    logging.info(f"Ignoring file: {filepath}")
                    continue  # Skip to the next file

                file_hash = process_file(filepath, use_yamllint, use_jsonlint)
                if file_hash:
                    hashes[relative_path] = file_hash

        if not recursive:
            # os.walk yields the top level first, so breaking here is what
            # non recursive means. Nothing sorts the walk, so the order
            # files are hashed in is whatever the filesystem hands over,
            # which only shows in the log, never in the result.
            break  # Only process the top-level directory

    return hashes


def main():
    """
    Main function to parse arguments, process configuration files/directories,
    and compare SHA-256 hashes to detect configuration drift.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if len(args.config_files) != len(args.environments):
        parser.error("The number of configuration files/directories must match the number of environments.")
        sys.exit(1)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    environment_hashes = {}
    for config_path, env_name in zip(args.config_files, args.environments):
        # Environment names are dictionary keys, so naming two paths
        # with the same environment silently discards the first one's
        # hashes when this line runs again. The count check in
        # setup_argparse compares counts, not uniqueness.
        environment_hashes[env_name] = {}
        if os.path.isfile(config_path):
            # process single file, keyed by its bare file name so the same
            # file at a different path in another environment shares the key
            # A path handed in as a single file bypasses the file types
            # filter entirely. The extension list only governs directory
            # walks, so an operator can hash a .txt file by naming it
            # directly, deliberately or by accident.
            file_hash = process_file(config_path, args.use_yamllint, args.use_jsonlint)
            if file_hash:
                environment_hashes[env_name][os.path.basename(config_path)] = file_hash
        elif os.path.isdir(config_path):
            environment_hashes[env_name] = process_directory(config_path, args.file_types, args.recursive, args.ignore_patterns, args.use_yamllint, args.use_jsonlint)
        else:
            logging.error(f"Invalid config path: {config_path}.  Must be a file or directory.")
            sys.exit(1)


    for env_name, env_hashes in environment_hashes.items():
        logging.info(f"Hashed {len(env_hashes)} file(s) for environment {env_name}.")

    if sum(len(env_hashes) for env_hashes in environment_hashes.values()) == 0:
        logging.error("No files were hashed for any environment. Nothing was compared.")
        sys.exit(1)

    # Compare hashes across environments
    all_files = set()
    for env_hashes in environment_hashes.values():
        all_files.update(env_hashes.keys())

    drift_detected = False
    for filepath in all_files:
        hashes = {}
        for env_name, env_hashes in environment_hashes.items():
            hashes[env_name] = env_hashes.get(filepath)

        # Check if hash exists in all environments, if not log a warning.
        # A file missing from an environment is itself drift.
        if None in hashes.values():
            drift_detected = True
            for env, hash_value in hashes.items():
                if hash_value is None:
                    logging.warning(f"File {filepath} not found in environment {env}")

        # Compare hashes, ignoring missing files
        # Expected, in the error below, means whichever environment
        # was listed first among those that have the file. There is no
        # canonical environment in my design; the first one just
        # becomes the reference the others are wrong against.
        first_hash = next((h for h in hashes.values() if h is not None), None)

        if first_hash:
            for env, hash_value in hashes.items():
                if hash_value is not None and hash_value != first_hash:
                    logging.error(f"Configuration drift detected for {filepath} in environment {env}. "
                                  f"Hash: {hash_value}, expected: {first_hash}")
                    drift_detected = True


    if drift_detected:
        sys.exit(1)

    if not drift_detected:
        logging.info("No configuration drift detected.")

    # Example Usage
    # This block can never run from the command line: argparse
    # above refuses a call with no arguments and exits before main
    # gets here. The examples survive as documentation for anyone
    # reading the file, which is the only place they are reachable.
    if not sys.argv[1:]: # check if no args passed
        print("\nUsage examples:")
        print("  # Compare two files:")
        print("  python misconfig-ConfigDriftDetector.py config/dev.yml config/prod.yml -e dev prod")
        print("  # Compare a directory of configuration files recursively:")
        print("  python misconfig-ConfigDriftDetector.py config/dev config/prod -e dev prod -r")
        print("  # Compare using yamllint and jsonlint and ignore log files:")
        print("  python misconfig-ConfigDriftDetector.py config/dev config/prod -e dev prod --use-yamllint --use-jsonlint --ignore-patterns *.log")


if __name__ == "__main__":
    main()