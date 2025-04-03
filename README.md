# misconfig-ConfigDriftDetector
Detects unexpected configuration changes across environments (e.g., dev, prod) using SHA-256 hashing and alerts on discrepancies. Can compare live systems or configuration files. - Focused on Check for misconfigurations in configuration files or infrastructure definitions

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
- `--ignore-patterns`: No description provided
- `--use-yamllint`: Run yamllint on YAML files before hashing.
- `--use-jsonlint`: Run jsonlint on JSON files before hashing.

## License
Copyright (c) ShadowStrikeHQ
