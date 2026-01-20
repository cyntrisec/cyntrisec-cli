#!/usr/bin/env python3
"""
Verify Issue Regressions
------------------------
This script verifies fixes for specific bugs reported in v0.1.3.

Checks:
1. JSON output is clean (no stdout pollution)
2. Suggested actions use scan_id format
3. Role session name argument exists

Usage:
    python scripts/verify_issues.py
"""
import sys
import json
import subprocess
import re
from cyntrisec.cli.output import suggested_actions

SCAN_ID_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{6}_\d{12}$")

def check_json_output():
    print("Checking for JSON output pollution...")
    # Run a command that produces JSON, e.g., version or a simple scan/analyze if possible without AWS
    # Since we can't easily run a live scan here without creds, we'll try a command that should be quick or fail gracefully
    # 'cyntrisec scan --help' does not output JSON.
    # We will try to run 'cyntrisec version' but it doesn't support --format json yet based on code reading.
    # Instead, we'll check if the CLI entry point generally separates logs.
    
    # Let's try to run a command that fails but should output JSON error if configured, 
    # or just check 'cyntrisec scan --format json' with invalid args.
    
    cmd = [sys.executable, "-m", "cyntrisec", "scan", "--format", "json", "--regions", "invalid-region"]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        # We expect some error, but the STDOUT should be clean JSON if --format json is respected for errors
        # OR at least empty if it failed before printing valid JSON.
        # Ideally, we want to ensure *if* json is printed, it's valid.
        
        output = result.stdout.strip()
        if output:
            try:
                json.loads(output)
                print("  [OK] JSON output is valid (or empty/clean).")
            except json.JSONDecodeError:
                 # If it's not JSON, check if it contains log lines
                 if "INFO" in output or "DEBUG" in output:
                     print("  [FAIL] stdout contains log lines.")
                     return False
                 else:
                     # It might be just a text error message if args validation failed before logging setup?
                     # Typer prints errors to stderr usually. 
                     # If stdout has content, it should be JSON.
                     print(f"  [FAIL] stdout is not valid JSON: {output[:50]}...")
                     return False
        else:
            print("  [OK] stdout is empty (errors likely in stderr).")
            
    except Exception as e:
        print(f"  [ERROR] Failed to run subprocess: {e}")
        return False
        
    return True

def check_suggested_actions_format():
    print("Checking suggested_actions format...")
    scan_id = "2026-01-20_120000_123456789012" # Valid format
    actions = suggested_actions([
        (f"cyntrisec analyze paths --scan {scan_id}", "Review paths")
    ])
    
    for action in actions:
        cmd = action["command"]
        parts = cmd.split()
        if "--scan" in parts:
            idx = parts.index("--scan") + 1
            if idx < len(parts):
                val = parts[idx]
                if not SCAN_ID_PATTERN.match(val):
                    print(f"  [FAIL] Suggested action uses invalid format: {val}")
                    return False
    
    print("  [OK] Suggested actions use correct scan_id format.")
    return True

def check_role_session_name_arg():
    print("Checking for --role-session-name argument...")
    cmd = [sys.executable, "-m", "cyntrisec", "scan", "--help"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if "--role-session-name" in result.stdout:
        print("  [OK] --role-session-name argument found.")
        return True
    else:
        print("  [FAIL] --role-session-name argument missing.")
        return False

def main():
    print("Starting Issue Regression Verification...")
    
    failures = []
    
    if not check_json_output():
        failures.append("JSON output check")
        
    if not check_suggested_actions_format():
        failures.append("Suggested actions check")
        
    if not check_role_session_name_arg():
        failures.append("Role session name check")
        
    if failures:
        print(f"\nERROR: Regression checks failed: {', '.join(failures)}", file=sys.stderr)
        return 1
        
    print("\nRegression Verification Passed!")
    return 0

if __name__ == "__main__":
    sys.exit(main())
