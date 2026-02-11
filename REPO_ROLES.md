## How gitgap works

gitgap scans a single repo for signs of:
- gittuf (source protection)
- in-toto (build attestation)
- SBOM (software bill of materials)
- TUF (secure distribution)

Each tool may span multiple repos. gitgap finds signals in one repo at a time. For now, human maps findings across repos to assess completeness.

### Example: TUF roles across repos

| Role | What it does | Example signals |
|------|--------------|-----------------|
| Repository tool | Creates TUF metadata (root.json, targets.json) | tuftool, tuf-repo-create |
| Build system | Signs metadata, adds targets | tuf-sign, kms-signer, metadata-update |
| OS/Client | Verifies signatures, applies updates | tuf-client, update-verifier |
| Hosting | Serves metadata + artifacts | (external infra, not in repo) |

### Example: gittuf roles across repos.

| Role | What it does | Example signals |
|------|--------------|-----------------|
| Repo admin | Creates root of trust, policy | gittuf trust init, refs/gittuf/policy |
| Policy author | Defines branch/file protections | gittuf policy add-rule, policy.json |
| Contributor | Signs commits (GPG/SSH), records RSL | git commit -S, gittuf rsl record |
| Verifier | Enforces policy on push | gittuf verify-ref, pre-receive hook |

A complete audit requires scanning each repo and mapping roles. gitgap finds the signals—human connects the dots.

Future: scan an org, map relationships automatically.