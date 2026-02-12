# gitgap

Scans repositories for supply chain security tooling:

- **gittuf** — source protection
- **in-toto** — build attestation
- **SBOM** — software bill of materials
- **TUF** — secure distribution

## Usage
```bash
python3 gitgap.py /path/to/repo
```

Results saved to `results/<timestamp>/<project>.json`

## Output
```
SCORE: 2/4
  gittuf:  No
  in-toto: No
  SBOM:    Yes
  TUF:     Yes
```

Human review required to interpret findings.