# Verified Linux Atomic catalog snapshot

The integration was verified with these immutable upstream revisions:

- Atomic Red Team:
  `a8f00488f3be0d6f8a967585848bb3817a590e31`
- Invoke-AtomicRedTeam:
  `8af478bb9e4637df568ac1e596553b025b16cd1b`

Resolve that exact snapshot:

```bash
./scripts/sync-sources.sh \
  a8f00488f3be0d6f8a967585848bb3817a590e31 \
  8af478bb9e4637df568ac1e596553b025b16cd1b
```

The parser returns:

```json
{
  "linux_test_count": 434,
  "catalog_digest": "bafad84aee3c29809a40a6dd85cecdaa15a3995a9623eb31ce16cc0089ee8c3e"
}
```

This is verification evidence, not a permanent inventory. To evaluate newer
upstream content, sync branch names or newer commits, inspect the changed
catalog and support-file digests, and explicitly approve a new campaign
digest.
