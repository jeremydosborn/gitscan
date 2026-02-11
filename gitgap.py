#!/usr/bin/env python3
"""

Scans repositories for signs of:
- gittuf (source protection)
- in-toto (build attestation)  
- SBOM (software bill of materials)
- TUF (secure distribution)

See REPO_ROLES.md for separation of concerns.
Human review required to interpret repo separation of concerns, and completeness of implementation.

Usage:
    python scan.py /path/to/repo
    python scan.py /path/to/repo -o results.json
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from core import gittuf, intoto, sbom, tuf


def scan_repo(repo_path: str) -> dict:
    repo_path = Path(repo_path).resolve()
    
    if not repo_path.exists():
        print(f"Error: {repo_path} does not exist", file=sys.stderr)
        sys.exit(1)
    
    project_name = repo_path.name
    
    results = {
        "project": project_name,
        "gittuf": gittuf.analyze(repo_path),
        "intoto": intoto.analyze(repo_path),
        "sbom": sbom.analyze(repo_path),
        "tuf": tuf.analyze(repo_path),
    }
    
    # Summary
    results["summary"] = {
        "gittuf": results["gittuf"]["found"],
        "intoto": results["intoto"]["found"],
        "sbom": results["sbom"]["found"],
        "tuf": results["tuf"]["found"],
        "score": sum([
            results["gittuf"]["found"],
            results["intoto"]["found"],
            results["sbom"]["found"],
            results["tuf"]["found"],
        ]),
        "max_score": 4
    }
    
    return results


def print_results(results: dict):
    print("\n" + "=" * 60)
    print(f"GITGAP RESULTS: {results['project']}")
    print("=" * 60)
    
    for check in ["gittuf", "intoto", "sbom", "tuf"]:
        data = results[check]
        status = "✓ FOUND" if data["found"] else "✗ NOT FOUND"
        print(f"\n{check.upper()}: {status}")
        
        if data["found"]:
            # Show top matches
            if data["matches"]:
                print(f"  Matches ({len(data['matches'])} matches):")
                print("  (preview only, full, unfiltered log recorded in results JSON)")
                for m in data["matches"][:3]:
                    rel_path = m["file"].split(results["project"])[-1]
                    print(f"    - {rel_path}:{m['line']}")
                    print(f"      {m['context'][:60]}...")
                if len(data["matches"]) > 3:
                    print(f"    ... and {len(data['matches']) - 3} more")
    
    print("\n" + "-" * 60)
    s = results["summary"]
    print(f"SCORE: {s['score']}/{s['max_score']}")
    print(f"  gittuf:  {'Yes' if s['gittuf'] else 'No'}")
    print(f"  in-toto: {'Yes' if s['intoto'] else 'No'}")
    print(f"  SBOM:    {'Yes' if s['sbom'] else 'No'}")
    print(f"  TUF:     {'Yes' if s['tuf'] else 'No'}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Scan repo")
    parser.add_argument("repo", help="Path to repository")
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress output")
    
    args = parser.parse_args()
    results = scan_repo(args.repo)

    # Auto-save to results/<timestamp>/
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_dir = Path(__file__).parent / "results" / timestamp
    results_dir.mkdir(parents=True, exist_ok=True)
    output_path = results_dir / f"{results['project']}.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to: {output_path}")
    
    if not args.quiet:
        print_results(results)
    
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to: {args.output}")


if __name__ == "__main__":
    main()
