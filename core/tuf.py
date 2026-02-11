"""TUF analyzer - secure distribution."""

from pathlib import Path
from typing import Dict, Any
from .base import analyze_repo, check_paths_exist

PATTERNS = [
    r"\btuf\b",
    r"\btough\b",
    r"theupdateframework",
]

INDICATOR_PATHS = ["tuf", "repository"]

TUF_METADATA = ["root.json", "targets.json", "snapshot.json", "timestamp.json"]


def analyze(repo_path: Path) -> Dict[str, Any]:
    result = analyze_repo(repo_path, PATTERNS)
    result["matches"].extend(check_paths_exist(repo_path, INDICATOR_PATHS))
    
    # Look for TUF metadata files
    metadata_found = []
    for mf in TUF_METADATA:
        files = list(repo_path.rglob(mf))[:3]
        for f in files:
            # Verify it looks like TUF metadata
            try:
                content = f.read_text()[:500]
                if '"signed"' in content or '"_type"' in content:
                    metadata_found.append(mf)
                    result["matches"].append({
                        "file": str(f),
                        "line": 0,
                        "pattern": f"tuf_metadata:{mf}",
                        "context": f"TUF metadata: {mf}",
                    })
            except Exception:
                pass
    
    result["found"] = len(result["matches"]) > 0
    return result
