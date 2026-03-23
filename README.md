# gitscan

Config-driven repo scanner with anonymous research survey using threshold cryptography.

gitscan is an early proof of concept and reference implementation of [dat-p](https://github.com/jeremydosborn/dat-p-spec) (Distributed Anonymous Testimony Protocol). Both are experimental and have not been independently audited.

## What it does

Scans repositories for patterns defined in YAML configs, then optionally collects anonymous survey responses about those results. Survey responses are encrypted with age and split using Shamir's Secret Sharing, distributing shares across multiple endpoints.

## Security Properties

| Attack | Result |
|--------|--------|
| Compromise 1 endpoint | Useless (need 2 of 3) |
| Compromise 2 endpoints | Still encrypted (need private key) |
| Compromise 2 endpoints + private key | Get responses, but no attribution |
| Steal tokens | Can submit on behalf of others (dedupe keeps first) |
| Flood with garbage | Rate-limited by endpoint; garbage fails decryption and is discarded |

Shamir’s secret-sharing scheme provides information-theoretic confidentiality for the split secret (individual shares reveal nothing about the secret), assuming correct implementation and fresh randomness.

## Flow

```
ADMIN                                    PARTICIPANT
─────                                    ───────────
gitscan-admin init                        
  → generates keypair + salt             

gitscan-admin tokens <count>
  → outputs: publickey.uniqueid tokens
  → share tokens/usage via secure channel
                                         gitscan scan /repo \
                                           --config supply \
                                           --token <token> \
                                           --endpoint shard1.survey.com
                                         
                                           → scans repo (patterns from yaml)
                                           → asks one or more questions
                                           → encrypts response (age)
                                           → splits into 3 shares (Shamir 2-of-3)
                                           → POSTs to 3 endpoints

gitscan-admin aggregate --key private.key
  → logs counts (before decrypt)
  → dedupes by submission ID (keeps first)
  → reconstructs shares from endpoints (2 of 3)
  → decrypts with private key
  → outputs aggregates only
  → deletes individual shares
```

## Installation

```bash
# Clone
git clone https://github.com/jeremydosborn/gitscan
cd gitscan

# Setup

#install yaml
pip install pyyaml

# Install age (for encryption)
brew install age    # macOS
apt install age     # Debian/Ubuntu
```

## Usage

### Admin: Run a Survey

```bash
# Initialize survey (generates keypair)
python3 gitscan-admin.py init

# Generate tokens for participants
python3 gitscan-admin.py tokens 50 > tokens.csv

# Share tokens via secure channel, or use locals in dev

# Check status
python3 gitscan-admin.py status

# Aggregate after survey closes
python3 gitscan-admin.py aggregate --key ~/.gitscan-admin/survey/private.key

# Permanently close survey (optional)
python3 gitscan-admin.py destroy-key
```

### Participant: Respond to Survey

```bash
# Scan repo and respond
python3 gitscan.py /path/to/repo \
  --config supply \
  --token <your-token> \
  --endpoint shard1.survey.com
```

## Configs

Scan patterns are defined in YAML:

Example:

```yaml
name: "Supply Chain Security"
version: 4

questions:
  - text: "Do you commit to answering honestly?"
    type: single_select
    options:
      y: "Yes"
      exit: "No — exit survey"

  - text: "Which mechanisms does your organization use?"
    type: multi_select
    options:
      a: "Signing"
      b: "SBOM"
      c: "Attestation"

  - text: "How mature is your implementation?"
    type: likert
    options:
      1: "Not mature"
      5: "Fully mature"

scanners:
  tuf:
    name: "TUF"
    patterns:
      - '\btuf\b'
    paths:
      - "tuf"
    files:
      - "root.json"
```

List available configs:

```bash
python3 gitscan.py --list-configs
```

## Architecture

```
gitscan/
├── gitscan.py           # scanner + survey client
├── gitscan-admin.py     # admin CLI
├── configs/
│   └── supply.yaml   # supply chain security scan
└── submission/
    ├── bundle.py       # age encryption + Shamir splitting
    └── submit.py       # endpoint submission (local/remote)
```

## Token Format

Tokens are self-contained:

```
age1xxxxxxxxxx...xxxxx.abc123def456
└─────────────────────┘ └──────────┘
      public key         unique id
```

The public key encrypts the response. The unique ID deduplicates submissions.

## Token Security

Tokens are bearer credentials. Possession of one valid token allows exactly one submission for that token. If the full token list is disclosed before distribution, survey integrity may be affected.

## License

This project is licensed under the **Apache License 2.0**. See the LICENSE AND CONTRIBUTING files for details.