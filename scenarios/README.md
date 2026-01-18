# Scenarios

This folder contains synthetic demo snapshots for documentation and demos.
The data is fake and safe to share.

## Use the demo snapshots

These snapshots are stored in a filesystem layout compatible with the CLI.
To run the CLI against the demo data, point `HOME` (and `USERPROFILE` on
Windows) at the `scenarios/demo-snapshots` directory:

```powershell
$env:HOME = "$PWD/scenarios/demo-snapshots"
$env:USERPROFILE = "$PWD/scenarios/demo-snapshots"
python -m cyntrisec analyze paths --scan 2026-01-18_000000_123456789012 --format agent
```

```bash
export HOME="$PWD/scenarios/demo-snapshots"
export USERPROFILE="$PWD/scenarios/demo-snapshots"
python -m cyntrisec analyze paths --scan 2026-01-18_000000_123456789012 --format agent
```

You can also copy the `scenarios/demo-snapshots/.cyntrisec` folder to
`~/.cyntrisec` and run commands normally.
