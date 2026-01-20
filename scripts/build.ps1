$ErrorActionPreference = "Stop"

Set-Location (Join-Path $PSScriptRoot "..")

Get-ChildItem -Path . -Filter "*.egg-info" -Recurse -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Remove-Item -Recurse -Force -ErrorAction SilentlyContinue dist, build, "src\\*.egg-info"

python -m build
