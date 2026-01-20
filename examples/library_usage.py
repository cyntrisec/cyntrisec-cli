import sys
import os

# Example: Programmatic usage of Cyntrisec
#
# This script demonstrates how you might wrap Cyntrisec CLI commands
# or potential future library calls to integrate into your own workflow.

def main():
    print("Cyntrisec Library Usage Example")
    print("===============================")
    
    # Currently, the most stable public interface is the CLI itself.
    # While you can import internals, they are subject to change.
    # Here is how to invoke the CLI from Python in a structured way.
    
    import subprocess
    import json
    
    # 1. Inspect Capabilities
    print("[*] Checking Manifest...")
    res = subprocess.run(
        [sys.executable, "-m", "cyntrisec", "manifest", "--format", "json"],
        capture_output=True, text=True
    )
    
    if res.returncode == 0:
        manifest = json.loads(res.stdout)
        version = manifest.get("data", {}).get("version", "unknown")
        print(f"    - Cyntrisec Version: {version}")
    else:
        print(f"    - Error: {res.stderr}")

    # 2. Example: Parse a hypothetical output
    # (In a real scenario, you'd scan and then parse the JSON output)
    print("\n[*] Integration Strategy:")
    print("    To integrate Cyntrisec into your CI/CD pipeline script:")
    print("    1. Run `cyntrisec scan --role-arn ... --format json > scan.json`")
    print("    2. Load scan.json and check 'finding_count' or 'attack_path_count'")
    print("    3. Fail build if counts > threshold")
    
    print("\n[+] Example Done. Check 'scan_demo.sh' for a full data walkthrough.")

if __name__ == "__main__":
    main()
