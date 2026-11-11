# Verified macOS Atomic catalog snapshot

The integration was verified with these immutable upstream revisions:

- Atomic Red Team:
  `a8f00488f3be0d6f8a967585848bb3817a590e31`
- Invoke-AtomicRedTeam:
  `8af478bb9e4637df568ac1e596553b025b16cd1b`

Resolve that exact snapshot:

```bash
./scripts/sync-macos-atomic-sources.sh \
  a8f00488f3be0d6f8a967585848bb3817a590e31 \
  8af478bb9e4637df568ac1e596553b025b16cd1b
```

The parser returns:

```json
{
  "macos_test_count": 267,
  "catalog_digest": "3669ce5f6e0794d2732bb07e1244defc058142d222a506f99a3c1abb43dce3ea",
  "executors": {
    "sh": 198,
    "bash": 57,
    "powershell": 4,
    "manual": 8
  },
  "preferred_architectures": {
    "arm64": 1,
    "x86_64": 1,
    "any": 265
  }
}
```

This is verification evidence, not a permanent inventory. For a newer
upstream revision, sync it, inspect changed definitions and support-file
digests, and approve a new campaign digest.
