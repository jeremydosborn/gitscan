# gitgap

Scans repositories for signs of supply chain security tooling.

## Usage
```bash
python gitgap.py /path/to/repo
```

## What it scans for signs of

- **gittuf** — source protection
- **in-toto** — build attestation
- **SBOM** — software bill of materials
- **TUF** — secure distribution

See [REPO_ROLES.md] for full role definitions and completeness criteria. 

Human review required to interpret role attribution and completeness after initial scan.

## Output

- Screen: summary (found/not found)
- `results/<timestamp>/<project>.json`: full matches for human review