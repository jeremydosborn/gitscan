#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Jeremy D. Osborn

"""
gitgap-admin - Survey administration tool.

Commands:
    init        Initialize a new survey (generate keypair)
    tokens      Generate tokens for participant list
    aggregate   Aggregate responses (dedupe, reconstruct, decrypt, delete)
    status      Show pending submissions

Usage:
    gitgap-admin init
    gitgap-admin tokens emails.txt > tokens.csv
    gitgap-admin aggregate --key private.key
    gitgap-admin status
"""

import argparse
import csv
import hashlib
import hmac
import json
import secrets
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

# Import survey modules
sys.path.insert(0, str(Path(__file__).parent))
from submission import bundle, submit


# Admin directory
ADMIN_DIR = Path.home() / ".gitgap-admin"
SURVEY_DIR = ADMIN_DIR / "survey"


def cmd_init(args):
    """Initialize a new survey - generate age keypair."""
    
    print("=" * 60)
    print("INITIALIZING GITGAP SURVEY")
    print("=" * 60)
    
    # Create directories
    SURVEY_DIR.mkdir(parents=True, exist_ok=True)
    
    private_key_path = SURVEY_DIR / "private.key"
    public_key_path = SURVEY_DIR / "public.key"
    salt_path = SURVEY_DIR / "token.salt"
    
    # Check if already initialized
    if private_key_path.exists():
        print(f"\n⚠ Survey already initialized at {SURVEY_DIR}")
        response = input("Reinitialize? This will invalidate existing data. [y/N]: ").strip().lower()
        if response not in ('y', 'yes'):
            print("Aborted.")
            return 1
    
    # Generate age keypair
    print("\nGenerating age keypair...")
    
    try:
        result = subprocess.run(
            ["age-keygen"],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"✗ Failed to generate keypair: {result.stderr}")
            print("  Make sure 'age' is installed: https://github.com/FiloSottile/age")
            return 1
        
        lines = result.stdout.strip().split('\n')
        private_key = None
        public_key = None
        
        for line in lines:
            if line.startswith('AGE-SECRET-KEY-'):
                private_key = line
            elif 'public key:' in line:
                public_key = line.split('public key:')[1].strip()
        
        if not private_key or not public_key:
            print(f"✗ Could not parse age-keygen output")
            return 1
        
        # Save keys
        private_key_path.write_text(private_key + '\n')
        private_key_path.chmod(0o600)
        
        public_key_path.write_text(public_key + '\n')
        
        print(f"  ✓ Private key: {private_key_path}")
        print(f"  ✓ Public key:  {public_key_path}")
        
    except FileNotFoundError:
        print("✗ 'age-keygen' not found. Install age:")
        print("  brew install age  # macOS")
        print("  apt install age   # Debian/Ubuntu")
        return 1
    
    # Generate token salt
    print("\nGenerating token salt...")
    salt = secrets.token_hex(32)
    salt_path.write_text(salt)
    salt_path.chmod(0o600)
    print(f"  ✓ Token salt: {salt_path}")
    
    # Create endpoint directories
    print("\nCreating endpoint directories...")
    endpoints_dir = Path.home() / ".gitgap-survey" / "endpoints"
    for endpoint in submit.ENDPOINT_NAMES:
        (endpoints_dir / endpoint).mkdir(parents=True, exist_ok=True)
        print(f"  ✓ {endpoint}/")
    
    print("\n" + "=" * 60)
    print("SURVEY INITIALIZED")
    print("=" * 60)
    print(f"""
Next steps:

1. SECURE THE PRIVATE KEY
   {private_key_path}

2. GENERATE TOKENS
   gitgap-admin tokens emails.txt > tokens.csv

3. DISTRIBUTE TOKENS
   Send each participant their token and endpoint via secure channel.

4. AGGREGATE
   gitgap-admin aggregate --key {private_key_path}
""")
    
    return 0


def cmd_tokens(args):
    """Generate anonymous tokens."""

    # Load public key
    public_key_path = SURVEY_DIR / "public.key"
    if not public_key_path.exists():
        print("Error: Public key not found. Run 'gitgap-admin init' first.", file=sys.stderr)
        return 1

    public_key = public_key_path.read_text().strip()

    # Load salt
    salt_path = SURVEY_DIR / "token.salt"
    if not salt_path.exists():
        print("Error: Token salt not found. Run 'gitgap-admin init' first.", file=sys.stderr)
        return 1

    salt = salt_path.read_text().strip()

    writer = csv.writer(sys.stdout)
    writer.writerow(["token"])

    for _ in range(args.count):
        # Generate 256 bits of entropy
        unique_id = secrets.token_hex(32)

        submission_id = hmac.new(salt.encode(), unique_id.encode(), hashlib.sha256).hexdigest()

        # Token format: public_key.submission_id
        token = f"{public_key}.{submission_id}"
        writer.writerow([token])

    return 0


def cmd_status(args):
    """Show status of pending submissions."""
    
    submissions = submit.list_pending_submissions()
    
    print("=" * 60)
    print("SURVEY STATUS")
    print("=" * 60)
    
    if not submissions:
        print("\nNo pending submissions.")
        return 0
    
    # Count unique and total
    unique_count = len(submissions)
    total_shards = sum(len(shards) for shards in submissions.values())
    
    print(f"\nUnique submissions: {unique_count}")
    print(f"Total shards: {total_shards}")
    
    # Show per-endpoint counts
    endpoint_counts = {e: 0 for e in submit.ENDPOINT_NAMES}
    for submission_id, shards in submissions.items():
        for shard in shards:
            endpoint_counts[shard["endpoint"]] += 1
    
    print("\nShards per endpoint:")
    for endpoint, count in endpoint_counts.items():
        print(f"  {endpoint}: {count}")
    
    # Show submissions ready for aggregation (have 2+ shards)
    ready = [sid for sid, shards in submissions.items() if len(shards) >= 2]
    print(f"\nReady to aggregate (2+ shards): {len(ready)}")
    
    if args.verbose:
        print("\nSubmissions:")
        for submission_id, shards in sorted(submissions.items()):
            shard_list = ", ".join(f"shard{s['shard_idx']}" for s in sorted(shards, key=lambda x: x['shard_idx']))
            status = "✓" if len(shards) >= 2 else "○"
            print(f"  {status} {submission_id[:16]}... [{shard_list}]")
    
    return 0


def cmd_aggregate(args):
    """Aggregate submissions - dedupe, reconstruct, decrypt, aggregate, delete."""
    
    private_key_path = Path(args.key)
    if not private_key_path.exists():
        print(f"Error: Private key not found: {private_key_path}", file=sys.stderr)
        return 1
    
    print("=" * 60)
    print("AGGREGATING SURVEY RESPONSES")
    print("=" * 60)
    
    # Load pending submissions
    submissions = submit.list_pending_submissions()
    
    if not submissions:
        print("\nNo pending submissions to aggregate.")
        return 0
    
    # Filter to submissions with 2+ shards
    ready = {sid: shards for sid, shards in submissions.items() if len(shards) >= 2}
    
    # Count duplicates (submissions with multiple timestamps)
    duplicate_submissions = 0
    duplicate_shards = 0
    for submission_id, shards in ready.items():
        timestamps = set(s["timestamp"] for s in shards)
        if len(timestamps) > 1:
            duplicate_submissions += 1
            sorted_shards = sorted(shards, key=lambda x: x["timestamp"])
            first_timestamp = sorted_shards[0]["timestamp"]
            duplicate_shards += len([s for s in shards if s["timestamp"] != first_timestamp])
    
    total_shards = sum(len(shards) for shards in submissions.values())
    
    # Log before decrypt (no attribution possible)
    log_path = ADMIN_DIR / "aggregation.log"
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "unique_submissions": len(submissions),
        "ready_to_aggregate": len(ready),
        "duplicate_submissions": duplicate_submissions,
        "duplicate_shards_discarded": duplicate_shards,
        "total_shards": total_shards,
    }
    
    with open(log_path, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    
    print(f"\n--- PRE-DECRYPT LOG (saved to {log_path}) ---")
    print(f"  Unique submissions: {len(submissions)}")
    print(f"  Ready to aggregate: {len(ready)}")
    print(f"  Duplicate submissions: {duplicate_submissions}")
    print(f"  Duplicate shards to discard: {duplicate_shards}")
    print(f"  Total shards: {total_shards}")
    print("--- END LOG ---\n")
    
    if not ready:
        print("No submissions ready for aggregation (need 2+ shards each).")
        return 0
    
    # Deduplicate by submission_id - keep first (earliest timestamp)
    print("Deduplicating by submission ID (keeping first)...")
    
    deduped = {}
    
    for submission_id, shards in ready.items():
        sorted_shards = sorted(shards, key=lambda x: x["timestamp"])
        first_timestamp = sorted_shards[0]["timestamp"]
        
        first_shards = [s for s in sorted_shards if s["timestamp"] == first_timestamp]
        later_shards = [s for s in sorted_shards if s["timestamp"] != first_timestamp]
        
        deduped[submission_id] = first_shards
        
        for shard in later_shards:
            shard["_duplicate"] = True
    
    print(f"  Kept: {len(deduped)} unique submissions")
    print(f"  Duplicates discarded: {duplicate_shards} shards")
    
    # Reconstruct and aggregate
    print("\nReconstructing and decrypting...")
    
    aggregates = {
        "n": 0,
        "sum": 0,
        "distribution": {1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
        "aggregated_at": datetime.now().isoformat(),
    }
    
    files_to_delete = []
    errors = []
    
    for submission_id, shards in deduped.items():
        try:
            shares = []
            for shard in shards[:2]:
                share = submit.load_share(shard["filepath"])
                shares.append(share)
                files_to_delete.append(shard["filepath"])
            
            for shard in shards[2:]:
                files_to_delete.append(shard["filepath"])
            
            payload = bundle.reconstruct_submission(shares, str(private_key_path))
            
            response = payload.get("response") or payload.get("internal_score")
            if response not in [1, 2, 3, 4, 5]:
                errors.append(f"invalid response: {response}")
                continue
            
            aggregates["n"] += 1
            aggregates["sum"] += response
            aggregates["distribution"][response] += 1
            
            print(f"  ✓ response: {response}")
            
        except Exception as e:
            errors.append(str(e))
    
    if aggregates["n"] > 0:
        aggregates["mean"] = round(aggregates["sum"] / aggregates["n"], 2)
    else:
        aggregates["mean"] = None
    
    # Delete duplicate shards too
    for submission_id, shards in ready.items():
        for shard in shards:
            if shard.get("_duplicate"):
                files_to_delete.append(shard["filepath"])
    
    print(f"\nAggregation complete:")
    print(f"  Responses: {aggregates['n']}")
    print(f"  Mean: {aggregates['mean']}")
    print(f"  Distribution: {aggregates['distribution']}")
    
    if errors:
        print(f"\nErrors ({len(errors)}):")
        for e in errors:
            print(f"  ✗ {e}")
    
    # Save aggregates
    aggregates_path = ADMIN_DIR / "aggregates.json"
    
    if aggregates_path.exists():
        existing = json.loads(aggregates_path.read_text())
        print(f"\nMerging with existing aggregates (n={existing.get('n', 0)})...")
        
        aggregates["n"] += existing.get("n", 0)
        aggregates["sum"] += existing.get("sum", 0)
        for k in [1, 2, 3, 4, 5]:
            aggregates["distribution"][k] += existing.get("distribution", {}).get(str(k), 0)
        
        if aggregates["n"] > 0:
            aggregates["mean"] = round(aggregates["sum"] / aggregates["n"], 2)
    
    aggregates_path.write_text(json.dumps(aggregates, indent=2))
    print(f"\nAggregates saved to: {aggregates_path}")
    
    # Delete shares
    if files_to_delete:
        print(f"\nDeleting {len(files_to_delete)} share files...")
        
        if args.dry_run:
            print("  (dry run - no files deleted)")
        else:
            deleted = submit.delete_shares(files_to_delete)
            print(f"  ✓ Deleted {deleted} files")
    
    print("\n" + "=" * 60)
    print("AGGREGATION COMPLETE")
    print("=" * 60)
    print(f"""
Results:
  Total responses: {aggregates['n']}
  Mean score: {aggregates['mean']}
  
Distribution:
  1 (Much less complete):    {aggregates['distribution'][1]}
  2 (Somewhat less):         {aggregates['distribution'][2]}
  3 (About the same):        {aggregates['distribution'][3]}
  4 (Somewhat more):         {aggregates['distribution'][4]}
  5 (Much more complete):    {aggregates['distribution'][5]}

Individual responses have been deleted.
Only aggregate statistics remain.
""")
    
    return 0


def cmd_destroy_key(args):
    """Securely delete the private key."""
    
    private_key_path = SURVEY_DIR / "private.key"
    
    if not private_key_path.exists():
        print("No private key found.")
        return 0
    
    print("=" * 60)
    print("⚠ DESTROY PRIVATE KEY")
    print("=" * 60)
    print(f"""
This will permanently delete:
  {private_key_path}

After deletion:
  • No new responses can be decrypted
  • Survey is permanently closed
  • This cannot be undone
""")
    
    response = input("Type 'DESTROY' to confirm: ").strip()
    
    if response != "DESTROY":
        print("Aborted.")
        return 1
    
    # Overwrite with random data before deleting
    size = private_key_path.stat().st_size
    private_key_path.write_bytes(secrets.token_bytes(size))
    private_key_path.unlink()
    
    print(f"\n✓ Private key destroyed.")
    print("Survey is now permanently closed.")
    
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="gitgap survey administration"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command")
    
    # init
    init_parser = subparsers.add_parser("init", help="Initialize a new survey")
    
    # tokens
    tokens_parser = subparsers.add_parser("tokens", help="Generate tokens for participants")
    tokens_parser.add_argument("count", type=int, help="Number of tokens to generate")
    
    # status
    status_parser = subparsers.add_parser("status", help="Show pending submissions")
    status_parser.add_argument("-v", "--verbose", action="store_true", help="Show details")
    
    # aggregate
    agg_parser = subparsers.add_parser("aggregate", help="Aggregate responses")
    agg_parser.add_argument("-k", "--key", required=True, help="Path to private key")
    agg_parser.add_argument("--dry-run", action="store_true", help="Don't delete shares")
    
    # destroy-key
    destroy_parser = subparsers.add_parser("destroy-key", help="Permanently delete private key")
    
    args = parser.parse_args()
    
    if args.command == "init":
        return cmd_init(args)
    elif args.command == "tokens":
        return cmd_tokens(args)
    elif args.command == "status":
        return cmd_status(args)
    elif args.command == "aggregate":
        return cmd_aggregate(args)
    elif args.command == "destroy-key":
        return cmd_destroy_key(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())