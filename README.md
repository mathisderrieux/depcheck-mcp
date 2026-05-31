# depcheck-mcp

MCP server exposing **DepCheck** — a dependency auditor for AI coding agents — to Claude Code, Cursor, and any other MCP-compatible client.

DepCheck analyzes open-source packages (npm, PyPI, cargo, Go) for:

- **Vulnerabilities** (CVE/GHSA via OSV.dev)
- **License compatibility** (SPDX)
- **Maintenance status** (last release, downloads)
- **Typosquatting** (suspicious name detection)

Returns a verdict: **GO**, **REVIEW**, or **BLOCK** with reasoning.

## Installation

### Claude Code

```bash
claude mcp add depcheck npx -y depcheck-mcp
```

Then in any Claude Code session:

> Should I install the npm package `axios` version 1.5.0?

Claude will automatically call DepCheck and give you a security-aware answer.

### Cursor / Other MCP clients

Add to your MCP config:

```json
{
  "mcpServers": {
    "depcheck": {
      "command": "npx",
      "args": ["-y", "depcheck-mcp"]
    }
  }
}
```

## Configuration

Override the API endpoint via environment variable (defaults to the public hosted instance):

```bash
DEPCHECK_API_URL=https://your-self-hosted.example.com
```

## How it works

This MCP server is a thin client that exposes a single tool `depcheck_check` to MCP clients. It forwards requests to the DepCheck HTTP API which performs the actual analysis using public data sources (OSV.dev, deps.dev, npm/PyPI/crates registries).

- Hosted API: https://depcheck-production.up.railway.app
- API source code: https://github.com/mathisderrieux/depcheck

## Example output

```
Package: reactt@1.0.1 (npm)
Verdict: BLOCK  |  Score: 0/100
Summary: ⛔ Suspicious package name — possibly typosquatting react
License: non-standard
Last release: 3765 days ago
Weekly downloads: 9
⚠ TYPOSQUATTING SUSPECT — similar to: react
Suggested alternatives:
  - react: Likely the legitimate package you meant (similar name)
```

## License

MIT