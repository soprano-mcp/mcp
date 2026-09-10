# Soprano Connect MCP Server

<img src="images/soprano-logo.png" alt="Soprano Logo" height="32" style="display:inline;vertical-align:middle;margin:12px 0;">

[![Listed on mcpservers.org](https://mcpservers.org/badge.svg)](https://mcpservers.org/servers/soprano-mcp/mcp)

Soprano Connect MCP Server enables you to build AI agents that can communicate, engage customers, and manage communications workflows through the Soprano Connect platform using the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/docs/2026-07-28/getting-started/intro).

The Soprano Connect MCP Server enables AI assistants, copilots, autonomous agents, and enterprise applications to securely interact with Soprano Connect's global CPaaS platform. Using natural language, AI agents can send messages, manage customer data, administer accounts, and orchestrate communications across multiple channels in a controlled, enterprise-grade environment.

No complex API integrations. No custom middleware. Simply connect your MCP-compatible AI client and start building intelligent communications workflows — connect any MCP-compatible client (Claude, VS Code Copilot, Cursor, etc.) to the Soprano MCP server and let your agent send messages and check delivery status across multiple channels, all through natural language.

## 💡 Why Soprano MCP?

Soprano Connect MCP transforms communications capabilities into AI-native tools that can be consumed directly by AI agents. With Soprano MCP, AI agents can:

- Send omnichannel communications across all channels supported by Soprano Connect platform
- Manage contacts and customer contact lists
- Query messaging history and delivery status
- Automate customer engagement workflows
- Build AI-powered communications use cases without custom integration code
- Operate within an enterprise-grade security and governance framework

## 🛠️ Key Features

- Send communications through any channel supported by Soprano Connect such as SMS, RCS, WhatsApp, Viber, Email, Voice, Mobile Push
- Rich content per channel — WhatsApp (media, interactive buttons/lists, templates, location, reactions), RCS (rich cards, carousels, suggestions), Voice (text-to-speech, pre-recorded audio, Call Control Objects), Push Notification
- Batch and broadcast sending, plus single/batch message status lookups
- WhatsApp Business (WABA) template listing, and media upload/delete
- Pluggable upstream (Soprano) authentication — API Key, OAuth2 (client credentials), Basic, Legacy OAuth2, and a session-cookie outlier for WABA templates — selected per request, credentials supplied by the caller and never stored server-side

## 📋 Prerequisites

- A [Soprano Design](https://www.sopranodesign.com/) Connect API account, provisioned with a license for each channel you want to use
- Python 3.12+ and [uv](https://docs.astral.sh/uv/)
- AI agent or application with MCP client support

> Each tool/channel is only available if your Soprano account is subscribed to and provisioned for the corresponding service. Features outside your current subscription must be enabled via Soprano's onboarding or account management process before use.

### Table of Contents

- [💡 Why Soprano MCP?](#-why-soprano-mcp)
- [🔌 Transports](#-transports)
  - [Streamable HTTP](#streamable-http)
  - [stdio](#stdio)
- [✉️ Messaging Channels](#️-messaging-channels)
- [🧰 Available Tools](#-available-tools)
- [🤖 Agent Permission and Access Control](#-agent-permission-and-access-control)
- [🔐 Authentication](#-authentication)
- [🔒 Client Authentication (optional)](#-client-authentication-optional)
- [🚀 Installation & Running](#-installation--running)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## 🔌 Transports

The Soprano MCP server supports both of the transports defined by the MCP spec — unlike a hosted multi-tenant service, you run it yourself (locally or deployed), so there's a single endpoint/process rather than one per channel.

### Streamable HTTP

Supports [streamable HTTP transport](https://modelcontextprotocol.io/docs/learn/architecture#transport-layer) for remote/deployable use (e.g. behind an ALB, Lambda Function URL, or API Gateway). Point your MCP client at the server's `/mcp` endpoint, replacing `<mems-mcp-server-url>` with wherever you've deployed it (or `http://127.0.0.1:8000` if running locally).

**If the server has [Client Authentication](#-client-authentication-optional) (`MCP_CLIENT_AUTH_MODE=oauth2.1`) enabled with the Layer 2 fallback turned on** — the recommended setup for hosted deployments — no `X-Soprano-*` headers are needed at all:

```json
{
  "servers": {
    "mems-mcp (http)": {
      "type": "http",
      "url": "<mems-mcp-server-url>/"
    }
  }
}
```

Your MCP client will redirect you through an OAuth login/consent page, where you enter your Soprano Connect **API ID** and **API KEY** — that's the only credential you need to supply. The server uses it both to authenticate you (Layer 1) and, via the Layer 2 fallback, to authenticate its own calls to Soprano on your behalf, so per-request headers become unnecessary.

**Otherwise** (`MCP_CLIENT_AUTH_MODE=none`, or you want to pass different Soprano credentials per request regardless), supply Layer 2 credentials explicitly via `X-Soprano-*` headers instead:

```json
{
  "servers": {
    "mems-mcp (http)": {
      "type": "http",
      "url": "<mems-mcp-server-url>",
      "headers": {
        "X-Soprano-Auth-Method": "api_key",
        "X-Soprano-Api-Id": "${input:soprano-api-id}",
        "X-Soprano-Api-Key": "${input:soprano-api-key}"
      }
    }
  }
}
```

`X-Soprano-Domain-Url` can usually be left out: if the server's own public hostname follows the `mcp-` naming convention (e.g. `mcp-aus.sopranodesign.com`), it derives your Soprano domain automatically by stripping that prefix (`https://aus.sopranodesign.com`). Set the header explicitly only if your deployment doesn't follow that convention, or to target a different domain than the one implied by the hostname.

The `X-Soprano-*` headers above are for the `api_key` method — swap them for any of the other supported auth methods (see [Authentication](#-authentication) below) by using the matching header set instead:

```json
// oauth2 (client credentials)
"headers": {
  "X-Soprano-Auth-Method": "oauth2",
  "X-Soprano-Client-Id": "${input:soprano-client-id}",
  "X-Soprano-Client-Secret": "${input:soprano-client-secret}"
}
```

```json
// basic
"headers": {
  "X-Soprano-Auth-Method": "basic",
  "X-Soprano-Username": "${input:soprano-username}",
  "X-Soprano-Password": "${input:soprano-password}"
}
```

```json
// legacy_oauth2
"headers": {
  "X-Soprano-Auth-Method": "legacy_oauth2",
  "X-Soprano-Username": "${input:soprano-username}",
  "X-Soprano-Password": "${input:soprano-password}"
}
```

> The legacy `sse` transport (append the server's `--transport sse` flag, endpoint `/sse`) is also available for MCP clients that don't yet support streamable HTTP.

### stdio

For local use (e.g. launched as a subprocess by VS Code, Claude Desktop, etc.), run with `--transport stdio`. Since stdio has no HTTP headers, Soprano credentials are supplied via `SOPRANO_*` environment variables instead:

```json
{
  "servers": {
    "mems-mcp (stdio)": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--directory", "${workspaceFolder}", "mems-mcp", "--transport", "stdio"],
      "env": {
        "SOPRANO_DOMAIN_URL": "https://aus.sopranodesign.com",
        "SOPRANO_AUTH_METHOD": "api_key",
        "SOPRANO_API_ID": "${input:soprano-api-id}",
        "SOPRANO_API_KEY": "${input:soprano-api-key}"
      }
    }
  }
}
```

Same as above, swap the `env` block for any other auth method:

```json
// oauth2 (client credentials)
"env": {
  "SOPRANO_DOMAIN_URL": "https://aus.sopranodesign.com",
  "SOPRANO_AUTH_METHOD": "oauth2",
  "SOPRANO_CLIENT_ID": "${input:soprano-client-id}",
  "SOPRANO_CLIENT_SECRET": "${input:soprano-client-secret}"
}
```

```json
// basic
"env": {
  "SOPRANO_DOMAIN_URL": "https://aus.sopranodesign.com",
  "SOPRANO_AUTH_METHOD": "basic",
  "SOPRANO_USERNAME": "${input:soprano-username}",
  "SOPRANO_PASSWORD": "${input:soprano-password}"
}
```

```json
// legacy_oauth2
"env": {
  "SOPRANO_DOMAIN_URL": "https://aus.sopranodesign.com",
  "SOPRANO_AUTH_METHOD": "legacy_oauth2",
  "SOPRANO_USERNAME": "${input:soprano-username}",
  "SOPRANO_PASSWORD": "${input:soprano-password}"
}
```

## ✉️ Messaging Channels

All channels are exposed through one generic `send_message` tool (`channel` parameter selects the target) rather than one MCP server per channel — this keeps the tool surface (and token footprint) small while still giving access to every channel-specific rich content type the Connect API supports.

| Channel | `channel` value | Rich content supported |
|---|---|---|
| SMS | `sms` | Plain text only |
| WhatsApp | `whatsapp` | Media (image/video/document/audio), interactive buttons/lists, pre-approved templates, location, reactions, context (replies) |
| RCS | `rcs` | Rich cards, carousels, suggested replies/actions, media |
| Email | `email` | Plain text, CC/BCC |
| Voice | `voice` | Text-to-speech, pre-recorded audio file, Call Control Objects |
| Viber | `viber` | Plain text (rich content not documented by the Connect API guide — use the `extra` passthrough field) |
| Mobile Push Notification | `pushnotification` | Title + body |

Anything not covered by a typed parameter can be sent via `send_message`'s `extra` field, merged verbatim into the outgoing Connect API payload.

## 🧰 Available Tools

| Tool | Maps to |
|---|---|
| `send_message` | `POST /cgpapi/messages/{channel}` |
| `get_message_status` | `GET /cgpapi/messages/{channel}/{id}` |
| `send_batch` | `POST /cgpapi/batch/messages` |
| `get_batch_status` | `POST /cgpapi/batch/messages/status` |
| `send_broadcast` | `POST /cgpapi/broadcast/sms` |
| `list_whatsapp_templates` | `GET /cgpapi/waba/templates` |
| `upload_whatsapp_media` | `POST /cgpapi/waba/media/{source}` |
| `delete_whatsapp_media` | `DELETE /cgpapi/waba/media/{id}` |

## 🤖 Agent Permission and Access Control

Every tool is annotated with MCP's standard [tool annotations](https://modelcontextprotocol.io/specification/draft/server/tools#annotations) (`readOnlyHint`, `destructiveHint`, `openWorldHint`) so a client can apply governance before invoking it — e.g. `send_message`/`send_batch`/`send_broadcast`/`upload_whatsapp_media` are non-read-only and reach an open world (real message delivery/spend), and `delete_whatsapp_media` is additionally flagged destructive. Since sending messages has real-world cost and reputational impact, apply your MCP client/host's permission controls (confirmation prompts, allow-lists, scoped credentials) to these tools rather than granting an agent unrestricted access — see the MCP spec's own [implementation considerations](https://modelcontextprotocol.io/specification/draft/server/tools#security-considerations) for guidance.

## 🔐 Authentication

Soprano credentials are supplied **per request**, never stored server-side or cached between calls. How you supply them depends on transport (HTTP headers for `streamable-http`/`sse`, environment variables for `stdio`):

| Auth method | stdio env vars | HTTP headers |
|---|---|---|
| API Key | `SOPRANO_AUTH_METHOD=api_key`, `SOPRANO_API_ID`, `SOPRANO_API_KEY` | `X-Soprano-Auth-Method: api_key`, `X-Soprano-Api-Id`, `X-Soprano-Api-Key` |
| OAuth2 (client credentials) | `SOPRANO_AUTH_METHOD=oauth2`, `SOPRANO_CLIENT_ID`, `SOPRANO_CLIENT_SECRET` | `X-Soprano-Auth-Method: oauth2`, `X-Soprano-Client-Id`, `X-Soprano-Client-Secret` |
| Basic | `SOPRANO_AUTH_METHOD=basic`, `SOPRANO_USERNAME`, `SOPRANO_PASSWORD` | `X-Soprano-Auth-Method: basic`, `X-Soprano-Username`, `X-Soprano-Password` |
| Legacy OAuth2 | `SOPRANO_AUTH_METHOD=legacy_oauth2`, `SOPRANO_USERNAME`, `SOPRANO_PASSWORD` | `X-Soprano-Auth-Method: legacy_oauth2`, `X-Soprano-Username`, `X-Soprano-Password` |
| Session cookie (`list_whatsapp_templates` only) | `SOPRANO_AUTH_METHOD=session_cookie`, `SOPRANO_SESSION_COOKIE` | `X-Soprano-Auth-Method: session_cookie`, `X-Soprano-Session-Cookie` |

Both transports also require the target domain — `SOPRANO_DOMAIN_URL` (stdio) or `X-Soprano-Domain-Url` (HTTP), e.g. `https://aus.sopranodesign.com`. For `streamable-http`/`sse`, this header can be omitted if the server's own public hostname follows the `mcp-` naming convention (e.g. `mcp-aus.sopranodesign.com`) — the domain is then derived automatically by stripping that prefix.

## 🔒 Client Authentication (optional)

Everything above is Layer 2 (this server → Soprano). Independently, you can also require
authentication on incoming MCP requests (Layer 1 — client → this server), off by default:

| Env var | Required | Description |
|---|---|---|
| `MCP_CLIENT_AUTH_MODE` | — | `none` (default) or `oauth2.1` |
| `MCP_OAUTH_ISSUER_URL` | if `oauth2.1` | Your Authorization Server's issuer URL(s) — comma-separated if this deployment fronts multiple domains. With the built-in self-hosted AS, this is derived automatically per-request from the caller's own `Host` header and can be left unset. |
| `MCP_OAUTH_AUDIENCE` | if `oauth2.1` | Expected token `aud` claim(s), comma-separated — same per-request derivation as above with the self-hosted AS. |
| `MCP_OAUTH_RESOURCE_SERVER_URL` | if `oauth2.1` | This server's own public URL — fallback default when a request's `Host` doesn't match any configured domain. |
| `MCP_OAUTH_JWKS_URI` | optional | Defaults to `{issuer}/.well-known/jwks.json` |
| `MCP_OAUTH_REQUIRED_SCOPES` | optional | Comma-separated required scopes |

Works with any standards-compliant OAuth2/OIDC Authorization Server (Auth0, Okta, Cognito, ...).

### Built-in self-hosted Authorization Server

Some MCP clients (confirmed: Zendesk Agent) require a full interactive OAuth 2.0 Authorization
Code + consent flow rather than just bearer-token verification. Rather than standing up a
separate IdP, this server can act as its own Authorization Server, using the caller's Connect
API ID/API KEY as their identity — the routes below are always mounted, and become useful once
`MCP_CLIENT_AUTH_MODE=oauth2.1` points `MCP_OAUTH_ISSUER_URL` at this same deployment:

- `GET`/`POST /oauth/authorize` — login+consent form, validating the API ID/API KEY against the Connect API domain derived from the request's own `Host` header (if it follows the `mcp-` convention), falling back to `MEMS_CONNECT_API_URL` otherwise
- `POST /oauth/token` — `authorization_code` (+ PKCE), `client_credentials`, and `refresh_token` grants
- `POST /oauth/register` — RFC 7591 Dynamic Client Registration; always registers a public (PKCE-secured) client, no `client_secret` issued
- `GET /.well-known/oauth-authorization-server` / `GET /.well-known/jwks.json` — RFC 8414/7517 discovery metadata

Most MCP clients discover required scopes automatically from that metadata. If yours doesn't, check its `scopes_supported` list at `{your-deployment-url}/.well-known/oauth-authorization-server` and configure them manually in the client.

| Env var | Required | Description |
|---|---|---|
| `MEMS_CONNECT_API_URL` | Yes | Fallback Connect API domain, used when a request's `Host` doesn't derive one via the `mcp-` convention (e.g. multiple domains fronted by one deployment) |
| `MCP_OAUTH_SIGNING_KEY` (or `MCP_OAUTH_SIGNING_KEY_SECRET_ARN` for an AWS Secrets Manager ARN) | Recommended | PEM RSA private key used to sign issued JWTs; an ephemeral key is generated (with a warning) if neither is set — fine for a single local process only |
| `MCP_OAUTH_CLIENTS_TABLE` / `_CODES_TABLE` / `_CONSENTS_TABLE` / `_AUDIT_TABLE` / `_REFRESH_TOKENS_TABLE` | optional | DynamoDB table names backing client/code/consent/audit/refresh-token storage (default to `mems-mcp-oauth-*`) — requires AWS credentials for `boto3` |
| `MCP_OAUTH_LAYER2_FALLBACK` / `MCP_OAUTH_LAYER2_CREDENTIALS_TABLE` | optional | Lets clients that can't send `X-Soprano-*` headers reuse the Connect identity they authenticated with at Layer 1 for Layer 2 calls too (opt-in; caches the real API KEY server-side, TTL-bounded) |

## 🚀 Installation & Running

```bash
git clone https://github.com/soprano-mcp/mcp.git
cd mcp
uv sync

# stdio (local subprocess, e.g. launched by an MCP client config)
uv run mems-mcp --transport stdio

# streamable-http (remote/deployable)
uv run mems-mcp --transport streamable-http
# host/port: MEMS_MCP_HOST (default 127.0.0.1), MEMS_MCP_PORT (default 8000)
```

## 🛠️ Troubleshooting

**Authentication issues**
- Confirm the `X-Soprano-*` headers (or `SOPRANO_*` env vars) match one of the 5 supported auth methods exactly, including the domain URL.
- `list_whatsapp_templates` is the one outlier requiring `session_cookie` auth — every other tool accepts the other 4 methods.

**Message delivery issues**
- Make sure the recipient's destination is valid for the channel (a phone number for SMS/WhatsApp/RCS/Voice/Viber, an email address for Email).
- Check `get_message_status` (or `get_batch_status` for SMS) — a successful `send_message` response only means Soprano *accepted* the request (`ENROUTE`), not that it was delivered.
- Some channels/accounts require an explicit license/provisioning on the Soprano side (e.g. Viber client connection) — a clean auth/payload but a licensing-style error back from the API means checking with Soprano support.

**Other issues**
- Errors from the Connect API are surfaced via the tool's error text (Soprano's `errorDescription` field). For deeper HTTP-level detail, see the Connect API guide's response/error format documentation.

## 🤝 Contributing

Issues and pull requests are welcome on the repository.

## 📄 License

[MIT](LICENSE)
