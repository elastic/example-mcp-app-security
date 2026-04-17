# Adding to Claude.ai

Claude.ai connects to MCP servers over HTTP. You need to expose your locally running server via a public tunnel.

## Steps

1. Start the local server:

```bash
npm start
# Server runs at http://localhost:3001/mcp
```

2. Expose it via a tunnel:

```bash
npx cloudflared tunnel --url http://localhost:3001
```

Cloudflared will print a public URL like `https://abc-123.trycloudflare.com`.

3. In Claude.ai, go to **Settings → Integrations** and add the tunnel URL as a custom MCP connector:

```
https://abc-123.trycloudflare.com/mcp
```
> Note the `/mcp` suffix.
> The tunnel URL changes each time you restart cloudflared. You'll need to update the connector in Claude.ai settings when this happens.

## Prerequisites

- The server must be [running locally](./setup-local.md) first.
- [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/) — installed automatically via `npx`, or install it directly for a persistent setup.
