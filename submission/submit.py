
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jeremy D. Osborn

"""
Distribute and manage survey response shares.

Security architecture:
1. Payload contains ONLY: version + response score (no identifying info)
2. Padded to fixed size (prevents length fingerprinting)
3. Encrypted with research team's public key (age)
4. Split into shares via Shamir secret sharing (2-of-3 threshold)
5. Each share destined for different infrastructure provider
"""

from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Optional
import urllib.request
import urllib.error

# Base directory for local survey data
SURVEY_DIR = Path.home() / ".gitscan-survey"

# Local endpoint names (would be real URLs in production)
ENDPOINT_NAMES = [
    "shard1.gitscan.dev",
    "shard2.gitscan.dev",
    "shard3.gitscan.dev",
]


def submit_shares(shares: List[Tuple[int, bytes]], submission_id: str, endpoints: Optional[List[str]] = None) -> bool:
    """
    Submit shares to endpoints (or save locally if no endpoints).
    
    Args:
        shares: List of (shard_index, share_bytes) tuples
        submission_id: Unique ID for deduplication
        endpoints: List of endpoint URLs, or None for local mode
        
    Returns:
        True if all shares submitted successfully
    """
    if endpoints is None:
        return submit_shares_local(shares, submission_id)
    else:
        return submit_shares_remote(shares, submission_id, endpoints)


def submit_shares_local(shares: List[Tuple[int, bytes]], submission_id: str) -> bool:
    """Save shares to local endpoint folders."""
    
    endpoints_dir = SURVEY_DIR / "endpoints"
    for endpoint in ENDPOINT_NAMES:
        (endpoints_dir / endpoint).mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    short_id = submission_id[:12]
    
    print("\n" + "-" * 60)
    print("SUBMITTING SHARES (local mode)")
    print("-" * 60)
    
    saved = []
    for shard_idx, share_data in shares:
        if shard_idx > len(ENDPOINT_NAMES):
            print(f"  ✗ No endpoint for shard {shard_idx}")
            continue
            
        endpoint_name = ENDPOINT_NAMES[shard_idx - 1]
        endpoint_dir = endpoints_dir / endpoint_name
        
        filename = f"{timestamp}_{short_id}_shard{shard_idx}.enc"
        filepath = endpoint_dir / filename
        
        with open(filepath, "wb") as f:
            f.write(submission_id.encode() + b"\n")
            f.write(share_data)
        
        saved.append(filepath)
        print(f"  ✓ Shard {shard_idx} → {endpoint_name}/")
    
    print(f"\nShares saved to: {endpoints_dir}")
    print("""
Architecture:
  • 3 shares on independent "endpoints" (local folders for demo)
  • 2-of-3 threshold for reconstruction
  • Submission ID for deduplication (keeps first only)
  • Use --endpoint for real HTTPS endpoints
""")
    
    return len(saved) == len(shares)


def submit_shares_remote(shares: List[Tuple[int, bytes]], submission_id: str, endpoints: List[str]) -> bool:
    """POST shares to remote HTTPS endpoints."""
    
    print("\n" + "-" * 60)
    print("SUBMITTING SHARES (remote)")
    print("-" * 60)
    
    success_count = 0
    
    for shard_idx, share_data in shares:
        if shard_idx > len(endpoints):
            print(f"  ✗ No endpoint for shard {shard_idx}")
            continue
        
        endpoint = endpoints[shard_idx - 1]
        url = f"https://{endpoint}/submit"
        
        # Build payload with submission_id header
        payload = submission_id.encode() + b"\n" + share_data
        
        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Content-Type": "application/octet-stream",
                    "X-Submission-ID": submission_id,
                },
                method="POST"
            )
            urllib.request.urlopen(req, timeout=30)
            print(f"  ✓ Shard {shard_idx} → {endpoint}")
            success_count += 1
        except urllib.error.URLError as e:
            print(f"  ✗ Shard {shard_idx} → {endpoint}: {e.reason}")
        except Exception as e:
            print(f"  ✗ Shard {shard_idx} → {endpoint}: {e}")
    
    print(f"\nSubmitted {success_count}/{len(shares)} shares")
    
    # Success if at least threshold (2) shares submitted
    return success_count >= 2


def list_pending_submissions(endpoint_names: Optional[List[str]] = None) -> dict:
    """
    List all submissions across local endpoints, grouped by submission_id.
    
    Returns:
        Dict mapping submission_id to list of shard info dicts
    """
    if endpoint_names is None:
        endpoint_names = ENDPOINT_NAMES
    
    endpoints_dir = SURVEY_DIR / "endpoints"
    submissions = {}
    
    for endpoint_name in endpoint_names:
        endpoint_dir = endpoints_dir / endpoint_name
        if not endpoint_dir.exists():
            continue
            
        for filepath in endpoint_dir.glob("*.enc"):
            try:
                with open(filepath, "rb") as f:
                    submission_id = f.readline().decode().strip()
                
                parts = filepath.stem.split("_")
                timestamp = "_".join(parts[:3])
                
                if submission_id not in submissions:
                    submissions[submission_id] = []
                
                submissions[submission_id].append({
                    "endpoint": endpoint_name,
                    "filepath": filepath,
                    "timestamp": timestamp,
                    "shard_idx": int(parts[-1].replace("shard", "")),
                })
                
            except Exception as e:
                print(f"Warning: Could not read {filepath}: {e}")
    
    return submissions


def load_share(filepath: Path) -> Tuple[int, bytes]:
    """Load a share from file."""
    with open(filepath, "rb") as f:
        f.readline()  # Skip submission_id header
        share_data = f.read()
    
    shard_idx = int(filepath.stem.split("_")[-1].replace("shard", ""))
    return (shard_idx, share_data)


def delete_shares(filepaths: List[Path]) -> int:
    """Delete share files."""
    deleted = 0
    for fp in filepaths:
        try:
            fp.unlink()
            deleted += 1
        except Exception as e:
            print(f"Warning: Could not delete {fp}: {e}")
    return deleted