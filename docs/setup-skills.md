# Installing Skills

Skills teach your AI agent *when* and *how* to use the tools. You can install them using the `skills` CLI with `npx`, or by cloning this repository and running the bundled installer script.

## npx (Recommended)

The fastest way to install skills — no need to clone this repository:

```sh
npx skills add elastic/example-mcp-app-security
```

This launches an interactive prompt to select skills and [target agents](https://github.com/vercel-labs/skills?tab=readme-ov-file#supported-agents). The CLI copies each skill folder into the correct location for the agent to discover.

Install all skills to all agents (non-interactive):

```sh
npx skills add elastic/example-mcp-app-security --all
```

## Local clone

If you prefer to work from a local checkout, or your environment does not have Node.js / npx, clone the repository and use the bundled bash installer:

```sh
git clone https://github.com/elastic/example-mcp-app-security.git
cd example-mcp-app-security
./scripts/install-skills.sh add -a <agent>
```

The script requires bash 3.2+ and standard Unix utilities (`awk`, `find`, `cp`, `rm`, `mkdir`).

| Flag | Description |
|------|-------------|
| `-a, --agent` | Target agent (repeatable) |
| `-s, --skill` | Install specific skills by name or glob |
| `-f, --force` | Overwrite already-installed skills |
| `-y, --yes` | Skip confirmation prompts |

List all available skills:

```sh
./scripts/install-skills.sh list
```

## Claude Desktop (zip upload)

Download the skill zips from the [latest GitHub release](https://github.com/elastic/wip-example-mcp-app-security/releases/latest):

- `alert-triage.zip`
- `attack-discovery-triage.zip`
- `case-management.zip`
- `detection-rule-management.zip`
- `generate-sample-data.zip`

In Claude Desktop: **Customize → Skills → Create Skill → Upload a skill** → upload each zip individually.

If you're building from source, you can generate the zips locally:

```bash
npm run skills:zip
# Produces dist/skills/<skill-name>.zip for each skill
```

## Supported agents

| Agent | Install directory |
|-------|-------------------|
| claude-code | `.claude/skills` |
| cursor | `.agents/skills` |
| codex | `.agents/skills` |
| opencode | `.agents/skills` |
| pi | `.pi/agent/skills` |
| windsurf | `.windsurf/skills` |
| roo | `.roo/skills` |
| cline | `.agents/skills` |
| github-copilot | `.agents/skills` |
| gemini-cli | `.agents/skills` |

## Updating skills

**npx:** Check whether any installed skills have changed upstream, then pull the latest:

```sh
npx skills check
npx skills update
```

**Local clone:** Re-run the installer with `--force` to overwrite existing skills:

```sh
git pull
./scripts/install-skills.sh add -a <agent> --force
```

Without `--force` the script skips skills that are already installed.
