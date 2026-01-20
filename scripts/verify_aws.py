#!/usr/bin/env python3
"""
Verify AWS Connectivity and Scan
--------------------------------
This script verifies that the current environment can successfully authenticate
to AWS and run a basic scan.

Usage:
    python scripts/verify_aws.py
"""
import os
import sys
import argparse
from cyntrisec.aws import AwsScanner
from cyntrisec.storage import FileSystemStorage

def main():
    parser = argparse.ArgumentParser(description="Verify AWS connectivity and scan.")
    parser.add_argument("--region", default="us-east-1", help="AWS region to scan (default: us-east-1)")
    parser.add_argument("--role-arn", help="AWS role ARN to assume")
    parser.add_argument("--external-id", help="External ID for role assumption")
    parser.add_argument("--profile", help="AWS profile to use")
    args = parser.parse_args()

    print(f"Starting AWS Verification...")
    print(f"  Region: {args.region}")
    if args.role_arn:
        print(f"  Role ARN: {args.role_arn}")
    if args.profile:
        print(f"  Profile: {args.profile}")

    try:
        storage = FileSystemStorage()
        scanner = AwsScanner(storage)
        
        print("Scanners initialized. Starting scan...")
        
        regions = [r.strip() for r in args.region.split(",")]
        snapshot = scanner.scan(
            regions=regions,
            role_arn=args.role_arn,
            external_id=args.external_id,
            profile=args.profile
        )
        
        print("\nScan Completed Successfully!")
        print(f"  Snapshot ID: {snapshot.id}")
        print(f"  Assets: {snapshot.asset_count}")
        print(f"  Relationships: {snapshot.relationship_count}")
        print(f"  Findings: {snapshot.finding_count}")
        print(f"  Attack Paths: {snapshot.path_count}")
        
        if snapshot.errors:
            print("\nWarnings:")
            for err in snapshot.errors:
                print(f"  - {err}")
        
        return 0
        
    except Exception as e:
        print(f"\nERROR: Scan failed: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
