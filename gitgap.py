#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Jeremy D. Osborn

"""
gitgap - Config-driven repo scanner with anonymous research survey.

Scans repositories for patterns defined in YAML config files.
Optionally collects anonymous, encrypted survey response.

Usage:
    gitgap scan /path/to/repo --config tufcheck
    gitgap scan /path/to/repo --config /path/to/custom.yaml
"""
import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

import yaml

from submission import bundle, submit


# Default configs directory
CONFIGS_DIR = Path(__file__).parent / "configs"


def load_config(config_name: str) -> Dict[str, Any]:
    """Load scan config from yaml file."""
    # Check if it's a path or a name
    if config_name.endswith('.yaml') or config_name.endswith('.yml'):
        config_path = Path(config_name)
    else:
        config_path = CONFIGS_DIR / f"{config_name}.yaml"
    
    if not config_path.exists():
        print(f"Error: Config not found: {config_path}", file=sys.stderr)
        print(f"Available configs: {list_configs()}", file=sys.stderr)
        sys.exit(1)
    
    with open(config_path) as f:
        return yaml.safe_load(f)


def list_configs() -> List[str]:
    """List available config names."""
    if not CONFIGS_DIR.exists():
        return []
    return [f.stem for f in CONFIGS_DIR.glob("*.yaml")]


def scan_file(filepath: Path, patterns: List[re.Pattern]) -> List[Dict[str, Any]]:
    """Scan a file for patterns."""
    matches = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                for pattern in patterns:
                    if pattern.search(line):
                        matches.append({
                            "file": str(filepath),
                            "line": line_num,
                            "pattern": pattern.pattern,
                            "context": line.strip()[:200],
                        })
    except Exception:
        pass
    return matches


def scan_repo(repo_path: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Scan repo using config-defined patterns."""
    repo_path = Path(repo_path).resolve()
    
    if not repo_path.exists():
        print(f"Error: {repo_path} does not exist", file=sys.stderr)
        sys.exit(1)
    
    project_name = repo_path.name
    scanners = config.get("scanners", {})
    
    # Skip dirs
    skip_dirs = {".git", "node_modules", "vendor", "target", "build", "dist", "__pycache__"}
    
    # Collect all files
    files = []
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for filename in filenames:
            files.append(Path(root) / filename)
    
    results = {
        "project": project_name,
        "config": config.get("name", "unknown"),
    }
    
    # Run each scanner
    for scanner_id, scanner_config in scanners.items():
        scanner_matches = []
        
        # Compile patterns
        patterns = [re.compile(p, re.IGNORECASE) for p in scanner_config.get("patterns", [])]
        
        # Scan files for patterns
        for filepath in files:
            scanner_matches.extend(scan_file(filepath, patterns))
        
        # Check for indicator paths
        for rel_path in scanner_config.get("paths", []):
            full_path = repo_path / rel_path
            if full_path.exists():
                scanner_matches.append({
                    "file": str(full_path),
                    "line": 0,
                    "pattern": f"path:{rel_path}",
                    "context": f"Path exists: {rel_path}",
                })
        
        # Check for indicator files (glob patterns)
        for file_pattern in scanner_config.get("files", []):
            for match in repo_path.rglob(file_pattern):
                scanner_matches.append({
                    "file": str(match),
                    "line": 0,
                    "pattern": f"file:{file_pattern}",
                    "context": f"File matched: {match.name}",
                })
        
        results[scanner_id] = {
            "name": scanner_config.get("name", scanner_id),
            "description": scanner_config.get("description", ""),
            "found": len(scanner_matches) > 0,
            "matches": scanner_matches,
        }
    
    # Build summary
    results["summary"] = {
        scanner_id: results[scanner_id]["found"]
        for scanner_id in scanners.keys()
    }
    results["summary"]["scan_score"] = sum(results["summary"].values())
    results["summary"]["max_score"] = len(scanners)
    
    return results


def print_results(results: Dict[str, Any], config: Dict[str, Any]):
    """Print scan results."""
    scanners = config.get("scanners", {})
    
    print("\n" + "=" * 60)
    print(f"GITGAP RESULTS: {results['project']}")
    print(f"Config: {results['config']}")
    print("=" * 60)
    
    for scanner_id in scanners.keys():
        data = results[scanner_id]
        status = "✓ FOUND" if data["found"] else "✗ NOT FOUND"
        print(f"\n{data['name'].upper()}: {status}")
        
        if data["found"] and data["matches"]:
            print(f"  Matches ({len(data['matches'])} total):")
            for m in data["matches"][:3]:
                rel_path = m["file"].split(results["project"])[-1]
                print(f"    - {rel_path}:{m['line']}")
                print(f"      {m['context'][:60]}...")
            if len(data["matches"]) > 3:
                print(f"    ... and {len(data['matches']) - 3} more")
    
    print("\n" + "-" * 60)
    s = results["summary"]
    print(f"SCAN SCORE: {s['scan_score']}/{s['max_score']}")
    for scanner_id in scanners.keys():
        name = scanners[scanner_id].get("name", scanner_id)
        print(f"  {name}: {'Yes' if s[scanner_id] else 'No'}")
    print()


def save_results(results: Dict[str, Any]) -> Path:
    """Save results to JSON file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_dir = Path(__file__).parent / "results" / timestamp
    results_dir.mkdir(parents=True, exist_ok=True)
    output_path = results_dir / f"{results['project']}.json"
    
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    
    return output_path


def prompt_survey(config: Dict[str, Any]) -> bool:
    """Prompt user to participate in survey."""
    print("\n" + "=" * 60)
    print("ANONYMOUS RESEARCH SURVEY")
    print("=" * 60)
    print("""
This scan is part of research. You can help by answering ONE
anonymous question.

Your response:
  - Contains NO identifying information
  - Is encrypted client-side before transmission
  - Cannot be linked back to you or this repository
""")
    
    response = input("Participate in research survey? [y/N]: ").strip().lower()
    return response in ('y', 'yes')


def run_survey(token: str, endpoint: str, config: Dict[str, Any]):
    """Run the survey with question from config."""
    # Parse token if provided
    if token:
        public_key, unique_id = token.rsplit('.', 1)
        submission_id = unique_id
    else:
        public_key = None
        unique_id = "_no_token_test_"
        submission_id = unique_id
    
    # Derive endpoints if provided
    if endpoint:
        base = endpoint.replace("shard1.", "")
        endpoints = [f"shard{i}.{base}" for i in [1, 2, 3]]
    else:
        endpoints = None
    
    # Get question from config
    question_config = config.get("question", {})
    question_text = question_config.get("text", "Rate from 1-5:")
    options = question_config.get("options", {})
    
    # Display question
    print(question_text)
    for val, label in sorted(options.items()):
        print(f"  {val} - {label}")
    
    # Collect response
    while True:
        try:
            response = input("\nYour response (0-5): ").strip()
            if response.lower() in ('q', 'quit', 'exit', ''):
                print("\nSurvey skipped.")
                return
            
            value = int(response)
            if value == 0:
                print("\nNo problem. Your response will not be recorded.")
                return
            if 1 <= value <= 5:
                break
            print("Please enter a number between 0 and 5")
        except ValueError:
            print("Please enter a valid number")
        except KeyboardInterrupt:
            print("\nSurvey skipped.")
            return
    
    payload = {"v": config.get("version", 1), "response": value}
    
    print("\nPreparing submission...")
    
    try:
        encrypted_shares = bundle.prepare_submission(payload, public_key)
    except FileNotFoundError as e:
        print(f"\n✗ Survey not configured: {e}")
        print("  Run 'gitgap-admin init' first to set up the survey.")
        return
    
    print(f"  ✓ Payload encrypted")
    print(f"  ✓ Split into {len(encrypted_shares)} shares (Shamir 2-of-3)")
    print(f"  ✓ Padded to fixed size")
    
    submit.submit_shares(encrypted_shares, submission_id, endpoints)


def main():
    parser = argparse.ArgumentParser(
        description="Config-driven repo scanner with anonymous survey"
    )
    parser.add_argument("repo", help="Path to repository")
    parser.add_argument("-c", "--config", default="tufcheck",
                        help="Scan config name or path (default: tufcheck)")
    parser.add_argument("-q", "--quiet", action="store_true", 
                        help="Suppress output")
    parser.add_argument("--token", help="Survey token (publickey.uniqueid)")
    parser.add_argument("--endpoint", help="Shard endpoint (e.g. shard1.survey.com)")
    parser.add_argument("--list-configs", action="store_true",
                        help="List available configs")
    
    args = parser.parse_args()
    
    if args.list_configs:
        print("Available configs:")
        for name in list_configs():
            print(f"  {name}")
        return
    
    # Load config
    config = load_config(args.config)
    
    # Scan
    results = scan_repo(args.repo, config)
    output_path = save_results(results)
    
    if not args.quiet:
        print_results(results, config)
        print(f"Results saved to: {output_path}")
        
        if prompt_survey(config):
            if args.token:
                run_survey(args.token, args.endpoint, config)
            else:
                print("\n✗ Survey requires a token.")
                print("  Run 'gitgap-admin tokens 1' to generate one.")


if __name__ == "__main__":
    main()