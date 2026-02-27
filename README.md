# GitGap

Config-driven repo scanner with anonymous research survey using threshold cryptography.

GitGap is an early proof of concept and reference implementation of [dat-p](https://github.com/jeremydosborn/dat-p-spec) (Distributed Anonymous Research Protocol). Both are experimental and have not been independently audited.

## What it does

Scans repositories for patterns defined in YAML configs, then optionally collects an anonymous survey response about those results. Survey responses are encrypted with age and split using Shamir's Secret Sharing, distributing shares across multiple endpoints.

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
gitgap-admin init                        
  → generates keypair + salt             

gitgap-admin tokens <count>
  → outputs: publickey.uniqueid tokens
  → share tokens/usage via secure channel
                                         gitgap scan /repo \
                                           --config tufcheck \
                                           --token <token> \
                                           --endpoint shard1.survey.com
                                         
                                           → scans repo (patterns from yaml)
                                           → asks one question
                                           → encrypts response (age)
                                           → splits into 3 shares (Shamir 2-of-3)
                                           → POSTs to 3 endpoints

gitgap-admin aggregate --key private.key
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
git clone https://github.com/jeremydosborn/gitgap
cd gitgap

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
python3 gitgap-admin.py init

# Generate tokens for participants
python3 gitgap-admin.py tokens 50 > tokens.csv

# Share tokens via secure channel, or use locals in dev

# Check status
python3 gitgap-admin.py status

# Aggregate after survey closes
python3 gitgap-admin.py aggregate --key ~/.gitgap-admin/submission/private.key

# Permanently close survey (optional)
python3 gitgap-admin.py destroy-key
```

### Participant: Respond to Survey

```bash
# Scan repo and respond
python3 gitgap.py /path/to/repo \
  --config tufcheck \
  --token <your-token> \
  --endpoint shard1.survey.com
```

### Local Testing (No Token)

```bash
python3 gitgap-admin.py init
python3 gitgap.py /path/to/repo --config tufcheck --no-token
python3 gitgap-admin.py aggregate --key ~/.gitgap-admin/submission/private.key
```

## Configs

Scan patterns are defined in YAML:

```yaml
# configs/tufcheck.yaml
name: "Supply Chain Security"
version: 1

question:
  text: |
    Compared to what's publicly visible, how complete is
    your organization's INTERNAL implementation?
  options:
    1: "Much less complete"
    2: "Somewhat less"
    3: "About the same"
    4: "Somewhat more"
    5: "Much more complete"
    0: "Prefer not to answer"

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
python3 gitgap.py --list-configs
```

## Architecture

```
gitgap/
├── gitgap.py           # scanner + survey client
├── gitgap-admin.py     # admin CLI
├── configs/
│   └── tufcheck.yaml   # supply chain security scan
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