
import os
import subprocess
import sys
import datetime
import shlex
from pathlib import Path

# Setup environment to use scenarios
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
SCENARIOS_DIR = PROJECT_ROOT / "scenarios" / "demo-snapshots"
OUTPUT_FILE = PROJECT_ROOT / "docs" / "cli-demo.md"

env = os.environ.copy()
# On Windows, both HOME and USERPROFILE are often used
env["HOME"] = str(SCENARIOS_DIR.absolute())
env["USERPROFILE"] = str(SCENARIOS_DIR.absolute())
env["PYTHONPATH"] = str(PROJECT_ROOT / "src")

SNAPSHOT_ID = "2026-01-18_000000_123456789012"

commands = [
    {"cmd": "manifest --format agent", "title": "cyntrisec manifest"},
    # Skipped scan to avoid auth errors in demo doc
    {"cmd": f"analyze paths --scan {SNAPSHOT_ID} --format agent", "title": "cyntrisec analyze paths"},
    {"cmd": f"cuts --snapshot {SNAPSHOT_ID} --format table", "title": "cyntrisec cuts (ROI Table)"},
    {"cmd": f"cuts --snapshot {SNAPSHOT_ID} --format json", "title": "cyntrisec cuts (JSON with Cost)"},
    {"cmd": f"waste --snapshot {SNAPSHOT_ID} --format table", "title": "cyntrisec waste"},
    {"cmd": f"can --snapshot {SNAPSHOT_ID} Admin access s3://prod-bucket --format json", "title": "cyntrisec can"},
    {"cmd": f"ask --snapshot {SNAPSHOT_ID} 'what can reach the database?' --format text", "title": "cyntrisec ask"},
]

def run_command(cmd_str):
    # Use shlex to handle quotes correctly
    # Note: On Windows, shlex.split might have issues with backslashes but here we use it for arguments mostly
    args = shlex.split(cmd_str, posix=False) if os.name == 'nt' else shlex.split(cmd_str)
    # Actually, shlex.split with posix=False is better for Windows paths, but our args are simple.
    # Let's stick to posix=True (default) because we use single quotes 'Query' which is POSIX style quoting.
    # PowerShell style quoting is different. But we are running from Python.
    # Wait, the cmd string has 'what can reach...'. POSIX split handles single quotes.
    args = shlex.split(cmd_str)
    
    full_cmd = [sys.executable, "-m", "cyntrisec"] + args
    try:
        # cyntrisec module run
        res = subprocess.run(
            full_cmd, 
            capture_output=True, 
            text=True, 
            env=env,
            cwd=PROJECT_ROOT
        )
        output = res.stdout if res.returncode == 0 else f"Error: {res.stderr}"
        
        # Sanitize PII / Absolute Paths
        # Normalize slashes for replacement
        scenarios_str = str(SCENARIOS_DIR.absolute())
        project_str = str(PROJECT_ROOT.absolute())
        
        # Common variations (forward vs back slash, JSON escaped)
        for path_str in [scenarios_str, project_str]:
            # Normal backslash (Windows)
            output = output.replace(path_str, "<demo_home>")
            # Forward slash (POSIX/URL)
            output = output.replace(path_str.replace("\\", "/"), "<demo_home>")
            # Double backslash (JSON escaped)
            output = output.replace(path_str.replace("\\", "\\\\"), "<demo_home>")
            
        return output
    except Exception as e:
        return str(e)

content = [
    "# Cyntrisec CLI - Demo Outputs",
    "",
    f"Generated: {datetime.datetime.utcnow()} UTC",
    "",
    "This file is generated from synthetic demo data only.",
    "",
    "## Command Outputs",
    ""
]

for item in commands:
    print(f"Running: {item['title']}")
    output = run_command(item['cmd'])
    content.append(f"### {item['title']}")
    content.append(f"```bash")
    content.append(f"cyntrisec {item['cmd']}")
    content.append(f"```")
    content.append(f"```") # Output block
    content.append(output.strip())
    content.append(f"```")
    content.append("")

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    f.write("\n".join(content))

print(f"Written to {OUTPUT_FILE}")
