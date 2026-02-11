| Role | Repo | What it does |
|------|------|--------------|
| Repository tool | aws/tough (includes tuftool) | Creates/manages TUF metadata (root.json, targets.json, etc.) |
| Build system | twoliter | Signs metadata updates with KMS, adds new targets |
| OS client | bottlerocket | updog fetches metadata, verifies signatures, applies updates |
| Hosting | AWS S3/CDN (external) | Serves metadata + artifacts to clients |

So a complete audit of "does Bottlerocket have TUF" requires scanning three repos plus knowing about external infra.

gitgap currently scans one repo at a time. It can tell you:
- bottlerocket: uses tough (client) ✓
- twoliter: uses tough-kms (signing) ✓
- aws/tough: has tuftool (repo creation) ✓

But it can't automatically connect them. That's manual interpretation—or future feature (scan an org, map relationships).

For now: scan each, note findings, human draws the lines.