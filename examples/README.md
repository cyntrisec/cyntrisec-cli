# Cyntrisec Examples

This directory contains examples for using Cyntrisec CLI and library.

## Contents

- **[scan_demo.sh](scan_demo.sh)**: A shell script demonstrating common CLI commands using the bundled demo snapshot.
- **[scan_demo.ps1](scan_demo.ps1)**: PowerShell version of the demo script.
- **[terraform_setup_example.tf](terraform_setup_example.tf)**: Example Terraform configuration for setting up the read-only IAM role.
- **[library_usage.py](library_usage.py)**: Python script demonstrating how to invoke Cyntrisec programmatically.
- **[mcp_config_example.json](mcp_config_example.json)**: Example configuration for adding Cyntrisec as an MCP server.

## Usage

You can run the shell demo directly (requires Cyntrisec installed):

```bash
bash scan_demo.sh
# OR for PowerShell
./scan_demo.ps1
```

Or run the Python example:

```bash
python library_usage.py
```
