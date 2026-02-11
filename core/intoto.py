"""in-toto analyzer - build attestation."""

from pathlib import Path
from typing import Dict, Any
from .base import analyze_repo, check_paths_exist

PATTERNS = [
    r"\bin-toto\b",
    r"\bin_toto\b",
    r"\bintoto\b",
]

INDICATOR_PATHS = [".in-toto", "in-toto"]


def analyze(repo_path: Path) -> Dict[str, Any]:
    result = analyze_repo(repo_path, PATTERNS)
    result["matches"].extend(check_paths_exist(repo_path, INDICATOR_PATHS))
    
    # Look for .link files
    link_files = list(repo_path.rglob("*.link"))[:10]
    for lf in link_files:
        result["matches"].append({
            "file": str(lf),
            "line": 0,
            "pattern": "*.link",
            "context": "in-toto link file",
        })
    
    # Look for layout files
    layout_files = list(repo_path.rglob("*layout*.json"))[:5]
    for lf in layout_files:
        result["matches"].append({
            "file": str(lf),
            "line": 0,
            "pattern": "layout.json",
            "context": "in-toto layout file",
        })
    
    result["found"] = len(result["matches"]) > 0
    return result
