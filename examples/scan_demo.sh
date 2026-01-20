#!/bin/bash

# cyntrisec-cli example: Data Analysis Demo
#
# This script demonstrates how to key CLI commands using the bundled demo snapshot.
# It sets up the environment to point to the repository's local scenarios folder,
# so you don't need real AWS credentials to run this.

# 1. Setup Environment to use local demo snapshots
#    (Overrides default ~/.cyntrisec location)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_HOME="$REPO_ROOT/scenarios/demo-snapshots"

if [ ! -d "$DEMO_HOME" ]; then
    echo "Error: Demo snapshots not found at $DEMO_HOME"
    exit 1
fi

export cyntrisec_HOME="$DEMO_HOME"
# Some systems might need HOME/USERPROFILE override if the tool invokes
# other configs, but cyntrisec usually respects its own config env var if it exists,
# or we can override HOME. For this demo we'll override HOME safely.
export HOME="$DEMO_HOME"

echo "Using demo data from: $DEMO_HOME"
SNAPSHOT_ID="2026-01-18_000000_123456789012"

# 2. Basic Information (Manifest)
echo "--------------------------------------------------------"
echo "1. Checking Tool Capabilities (Manifest)"
echo "--------------------------------------------------------"
python -m cyntrisec manifest --format text
echo ""

# 3. Analyze Paths (Attack Path Discovery)
echo "--------------------------------------------------------"
echo "2. Analyzing Attack Paths (Risk > 0.5)"
echo "--------------------------------------------------------"
python -m cyntrisec analyze paths --scan "$SNAPSHOT_ID" --min-risk 0.5 --format table
echo ""

# 4. Remediation (Cuts)
echo "--------------------------------------------------------"
echo "3. Finding Optimal Remediations (Cuts)"
echo "--------------------------------------------------------"
# Shows the most efficient set of changes to block the paths found above.
python -m cyntrisec cuts --snapshot "$SNAPSHOT_ID" --format table
echo ""

# 5. Waste Analysis (Unused Permissions)
echo "--------------------------------------------------------"
echo "4. Analyzing Unused Permissions (Blast Radius)"
echo "--------------------------------------------------------"
python -m cyntrisec waste --snapshot "$SNAPSHOT_ID" --format table
echo ""

# 6. Compliance Check
echo "--------------------------------------------------------"
echo "5. Checking Compliance (CIS AWS)"
echo "--------------------------------------------------------"
python -m cyntrisec comply --dataset cis-aws --snapshot "$SNAPSHOT_ID" --format table || true
echo ""

echo "Demo complete!"
