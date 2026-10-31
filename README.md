![Banner](banner.png)

# misconfig-ConfigDriftDetector
Detects unexpected configuration changes across environments (e.g., dev, prod) using SHA-256 hashing and alerts on discrepancies. It compares configuration files and directories on this machine only. There is no live system or remote host comparison: every input is a local file or directory path given on the command line. - Focused on Check for misconfigurations in configuration files or infrastructure definitions

## Install
`git clone https://github.com/ShadowStrikeHQ/misconfig-configdriftdetector`

## Usage
`./misconfig-configdriftdetector [params]`

## Parameters
- `-h`: Show help message and exit
- `-e`: No description provided
- `-r`: Recursively search directories for configuration files.
- `-v`: Enable verbose logging.
- `-t`: No description provided
- `--ignore-patterns`: Glob patterns for files to skip, matched with fnmatch against the file name and the path, so `*.yaml` and `*.log` work as the examples show.
- `--use-yamllint`: Run yamllint on YAML files before hashing.
- `--use-jsonlint`: Run jsonlint on JSON files before hashing.

## How the comparison is keyed
Files are compared by their path relative to the environment root given for them. A directory input contributes each file's relative path, and a single file input contributes its bare file name. That is what lets `dev/app.yaml` and `prod/app.yaml` at different locations be compared with each other. A file that is missing from one environment counts as drift.

## Exit codes
- Exit 0: at least one file was hashed and compared, and no drift was found.
- Exit 1: drift was detected, a file was missing from an environment, an input path was invalid, or nothing was compared at all. An empty directory on one side, and a linter flag run where a missing yamllint or jsonlint binary dropped every file, both exit 1. The linter error names the missing binary, and each run logs how many files were hashed per environment.

## License
Copyright (c) ShadowStrikeHQ
