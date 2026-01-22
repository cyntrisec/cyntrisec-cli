# cyntrisec-cli example: Data Analysis Demo (PowerShell)
#
# This script demonstrates how to run cyntrisec CLI commands using the bundled demo snapshot.

# 1. Setup Environment to use local demo snapshots
$RepoRoot = Resolve-Path "$PSScriptRoot\.."
$DemoHome = Join-Path $RepoRoot "scenarios\demo-snapshots"

if (-not (Test-Path $DemoHome)) {
    Write-Error "Error: Demo snapshots not found at $DemoHome"
    exit 1
}

$env:cyntrisec_HOME = $DemoHome
# Override HOME/USERPROFILE safely for the demo session only
$env:USERPROFILE = $DemoHome
$env:HOME = $DemoHome

Write-Host "Using demo data from: $DemoHome"
$SnapshotId = "2026-01-18_000000_123456789012"

# 2. Basic Information (Manifest)
Write-Host "--------------------------------------------------------"
Write-Host "1. Checking Tool Capabilities (Manifest)"
Write-Host "--------------------------------------------------------"
python -m cyntrisec manifest --format json
Write-Host ""

# 3. Analyze Paths (Attack Path Discovery)
Write-Host "--------------------------------------------------------"
Write-Host "2. Analyzing Attack Paths (Risk > 0.5)"
Write-Host "--------------------------------------------------------"
python -m cyntrisec analyze paths --scan "$SnapshotId" --min-risk 0.5 --format table
Write-Host ""

# 4. Remediation (Cuts)
Write-Host "--------------------------------------------------------"
Write-Host "3. Finding Optimal Remediations (Cuts)"
Write-Host "--------------------------------------------------------"
python -m cyntrisec cuts --snapshot "$SnapshotId" --format table
Write-Host ""

# 5. Waste Analysis (Unused Permissions)
Write-Host "--------------------------------------------------------"
Write-Host "4. Analyzing Unused Permissions (Blast Radius)"
Write-Host "--------------------------------------------------------"
python -m cyntrisec waste --snapshot "$SnapshotId" --format table
Write-Host ""

# 6. Compliance Check
Write-Host "--------------------------------------------------------"
Write-Host "5. Checking Compliance (CIS AWS)"
Write-Host "--------------------------------------------------------"
python -m cyntrisec comply --framework cis-aws --snapshot "$SnapshotId" --format table
Write-Host ""

Write-Host "Demo complete!"
