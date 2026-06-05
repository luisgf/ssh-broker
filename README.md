# ssh-broker

SSH access broker with an **ephemeral CA** for AI agents. The model **never
receives a credential**: it requests a command to be executed on a host, and the
broker signs an ephemeral, scope-limited SSH certificate, opens the SSH connection
itself, and returns **only the command output**.

Three frontends share the same engine (`internal/broker`) and tool surface
(`internal/mcpserver`):

- **MCP stdio (local, recommended for personal use)** — `cmd/mcp-broker`. Tools:
  - `ssh_execute(server, command [, sudo, sudo_user, pty])` — one-shot, cert with `force-command`.
  - `ssh_session_open(server, mode [, sudo, sudo_user])` / `ssh_session_exec(session_id, command)` /
    `ssh_session_close(session_id)` — persistent session (connection reuse).
  - `ssh_list_servers()`.  
  No transport authentication: isolation comes from the fact that the process is
  launched by the user (as recommended by the MCP spec for stdio).
- **MCP HTTP+OAuth2/OIDC (remote, multi-user)** — `cmd/mcp-broker-http`, Streamable HTTP.
  Same tools, but each client authenticates with an **OIDC bearer token** that the
  broker validates locally against the issuer's JWKS. The user identity
  (`sub`/`preferred_username`) replaces `mcp-stdio` in the audit log and, if the
  token carries groups, they are forwarded to the signer for **per-user RBAC**.
  Publishes `/.well-known/oauth-protected-resource` (RFC 9728) for client
  discovery. See [Remote MCP frontend](#remote-mcp-frontend-oauth2oidc).
- **HTTP+mTLS** — `cmd/broker`, `POST /v1/ssh_run` (one-shot), for network agents
  authenticated with a client certificate.

## Signing mode: local or external service

The broker obtains certificates through the `internal/signer` interface:

- **Local (single-binary):** the broker holds the CA key (`ca_key`) and signs
  in-process. Policy (principal/source-address/allow_sudo/allow_pty) is inline in
  `hosts`. Simple.
- **External (recommended for production):** a **signing service** (`cmd/signer`)
  holds the CA key **and the policy**; the broker requests certs over HTTP+mTLS,
  sending an *intent* `{host, role, purpose, command?, sudo?, sudo_user?, pty?,
  ttl, pubkey}` and receiving the signed cert. **The broker never holds the CA
  key.** Activated via the `signer{ url, client_cert, client_key, ca }` block in
  the broker config.

Invariant: the **ephemeral private key is generated and stays in the broker**;
only the public key travels to the signing service. Policy (principal,
source-address, force-command by purpose, bastion port-forwarding, TTL, broker CN
authorization, sudo and PTY authorization) is enforced by the service → a
compromised broker cannot bypass it or steal the key.  
Independent dual audit: issuance at the service + execution at the broker,
correlated by `serial`. Key custody: PEM today, `crypto.Signer` from
KMS/HSM/Secure Enclave tomorrow (seam in `ca.LoadCAFromPEM` / `signer.Local`).

See `signer.example.json` and the `_signer_remoto_example` block in
`config.example.json`.

## ProxyJump and sessions

- **ProxyJump/bastion:** a host with `"jump": "<other-host>"` is reached through
  that bastion (chainable). The broker signs **one cert per hop** and opens
  `direct-tcpip` channels. The bastion cert carries `permit-port-forwarding`; the
  target cert does not. ⚠️ The `source_address` of the **target** must be the
  egress IP of the **bastion** (not the broker) — configure with the
  `source_address` override per host.
- **Sessions (pool/mux):** a session is a retained connection; **one cert per
  connection** (no `force-command`) and commands go as channels over it.
  - `mode=exec` (default): each command isolated, stdout/stderr separate.
  - `mode=shell`: a stateful `sh` that persists state (`cd`, variables).
    Limitations: no interactive commands that require input or binary output.
  - `mode=pty`: shell with PTY (pseudo-terminal). For programs that call
    `isatty()` or require a real TTY. Stdout and stderr are merged.
  - The reaper closes by `session_idle_seconds` / `session_max_seconds`.

## Privilege escalation (sudo NOPASSWD) and PTY

### sudo NOPASSWD

The broker supports privilege escalation via `sudo -n` (non-interactive,
NOPASSWD). Authorization is **policy-gated at the signer**: a compromised broker
cannot escalate on hosts that do not permit it.

**Configuration (per host):**

| Field (signer/config) | Description |
|---|---|
| `allow_sudo: true` | Enables escalation on this host. |
| `allowed_sudo_users: ["root","deploy"]` | Permitted target users. Empty = root only. |
| `allow_pty: true` | Allows `permit-pty` in the cert (required for `pty=true` / `mode=pty`). |

**Host-side** (`/etc/sudoers.d/broker`):

```
# SSH account 'deploy', escalation to root without password:
deploy ALL=(root) NOPASSWD: ALL

# Restricted to specific commands (recommended in production):
deploy ALL=(root) NOPASSWD: /usr/bin/systemctl, /usr/bin/journalctl
```

**How it works:**

- **One-shot** (`ssh_execute` with `sudo=true`): the signer bakes `sudo -n [-u U]
  -- /bin/sh -c '<cmd>'` into the cert's `force-command`. `sshd` enforces it; the
  broker cannot modify it. The prefix is part of the issuance audit.
- **`exec` session** with `sudo=true`: the signer returns `elevation_prefix`; the
  broker prepends it to each command individually.
- **`shell`/`pty` session** with `sudo=true`: the entire shell is launched under
  `sudo -n [-u U] -- /bin/sh`. The whole session runs elevated.

### PTY

A PTY is needed for programs that call `isatty()` (editors, interactive tools,
some diagnostic scripts).

- In `ssh_execute`: pass `pty=true` (requires `allow_pty: true` in the policy).
- In `ssh_session_open`: use `mode=pty` (implies `pty=true` automatically).
- Note: with PTY, `stdout` and `stderr` are **merged**; `Result.Stderr` will be
  empty.

## Why ssh-broker

- **Anti-exfiltration (prompt injection):** ephemeral key/cert live only in the
  broker's memory; they never enter the model's context.
- **Anti-reuse:** each cert carries a TTL of minutes, `source-address` (broker
  IP), and `force-command` (the requested command, including the sudo prefix if
  applicable). Useless outside of host/time/IP.
- **Controlled escalation:** `allow_sudo` and `allowed_sudo_users` live in the
  signer; the broker cannot escalate on hosts that have not authorized it.
- **CA compromise bounded:** one CA per host group; the signing key can live in an
  HSM/KMS via `crypto.Signer` (`ca.NewFromSSHSigner`).
- **Audit/non-repudiation:** append-only, chained and signed (Ed25519) log;
  `elevation` and `pty` fields in each entry; `sshd` with `LogLevel VERBOSE`
  correlates by serial.

## Authentication: client to broker

Three frontends, three mechanisms:

```
┌──────────────────────┬──────────────────────────────────┬────────────────────────┐
│  MCP stdio (local)   │  MCP HTTP+OAuth2/OIDC (network)  │  HTTP+mTLS (network)   │
│  cmd/mcp-broker      │  cmd/mcp-broker-http             │  cmd/broker            │
├──────────────────────┼──────────────────────────────────┼────────────────────────┤
│  No token.           │  OIDC bearer token               │  TLS client cert       │
│  Isolation by        │  validated locally against       │  (mTLS).               │
│  process (MCP spec). │  the issuer's JWKS.              │  CN of cert = caller.  │
├──────────────────────┼──────────────────────────────────┼────────────────────────┤
│  Caller.ID =         │  Caller.ID = user_claim          │  Caller.ID = CN        │
│  "mcp-stdio"         │  Caller.Groups = groups_claim    │  of client cert        │
└──────────────────────┴──────────────────────────────────┴────────────────────────┘
```

### OAuth2/OIDC flow (cmd/mcp-broker-http)

```
  MCP Client             mcp-broker-http               IdP (OIDC Issuer)
  ──────────             ───────────────               ─────────────────
       │                        │                             │
       │── POST /mcp ──────────►│                             │
       │                        │                             │
       │◄── 401 ────────────────│                             │
       │    WWW-Authenticate:   │                             │
       │    Bearer resource_    │                             │
       │    metadata="https://… │                             │
       │    /.well-known/oauth- │                             │
       │    protected-resource" │                             │
       │                        │                             │
       │── GET /.well-known/… ─►│                             │
       │◄── { authorization_    │                             │
       │      servers: [issuer]}│                             │
       │                        │                             │
       │──── Authorization Code + PKCE ─────────────────────►│
       │◄─── access_token (JWT) ─────────────────────────────│
       │                        │                             │
       │── POST /mcp ──────────►│                             │
       │   Authorization: Bearer│── (on startup) GET JWKS ──►│
       │   <JWT>                │   cached; auto-rotated.    │
       │                        │                             │
       │                        │  Verifier.Verify(JWT)       │
       │                        │  ├─ signature (local JWKS,  │
       │                        │  │  no round-trip)          │
       │                        │  ├─ iss / aud / exp         │
       │                        │  ├─ iat ≤ max_token_age     │
       │                        │  ├─ user_claim → UserID     │
       │                        │  └─ groups_claim → Groups   │
       │                        │                             │
       │◄── MCP response ───────│                             │
```

### Identity propagated to the signer

```
  Caller.ID     ──► broker audit log (traceability)
  Caller.Groups ──► Intent.EndUserGroups
                              │
                              │  HTTPS + mTLS (pki/broker.crt, CN=broker-1)
                              ▼
                         cmd/signer
                         POST /v1/sign
                         ├── RBAC by broker CN
                         │   CallerTable: CN → allowed_groups
                         │
                         ├── RBAC by end user (only if EndUserGroups != nil)
                         │   hp.Groups ∩ EndUserGroups ≠ ∅
                         │
                         └── signs ephemeral SSH certificate
```

## Authentication: broker to SSH server

### ① Ephemeral key pair generation

For each hop (bastion or target) the broker generates an Ed25519 pair in memory:

```
  ca.GenerateEphemeralKey()
  ├── priv (Ed25519) ──► stays in broker, NEVER leaves the process
  └── pub            ──► sent to signer along with the intent
```

### ② The signer signs the certificate (HTTPS + mTLS)

```
  Intent ──────────────────────────────────────────► cmd/signer
  ├── host, role (bastion | target)                      │
  ├── command, sudo?, sudo_user?, pty?                   │ RBAC by broker CN
  ├── end_user = Caller.ID                               │ RBAC by end user
  ├── end_user_groups = Caller.Groups                    │ PolicyTable.Resolve
  └── pub (ephemeral public key)                         │
                                                         │ ca.BuildAndSign(caKey, pub, constraints)
  Certificate ◄────────────────────────────────────────── │
  ├── ValidPrincipals: ["host:web01"]      ← principal
  ├── ValidAfter / ValidBefore             ← TTL (≤ 15 min)
  ├── source-address: "10.0.1.5"          ← broker IP (or bastion IP)
  ├── force-command: "sudo -n -- /bin/sh…"← one-shot; empty in sessions
  ├── permit-port-forwarding              ← bastion cert only
  └── permit-pty                          ← if allow_pty and pty requested
```

### ③ SSH connection to the target server

```
  broker                                        sshd (target :22)
  ──────                                        ─────────────────
     │
     │  TCP :22
     │─────────────────────────────────────────►
     │
     │  broker verifies sshd host key
     │  FixedHostKey(hp.HostKey)                ← pinned in signer.json;
     │  rejects if mismatch                        no TOFU
     │
     │  presents: certSigner{priv, cert}         sshd verifies:
     │─────────────────────────────────────────► ├─ cert signature (TrustedUserCAKeys)
     │                                           ├─ principal ∈ AuthorizedPrincipals/<user>
     │                                           ├─ now ∈ [ValidAfter, ValidBefore]
     │                                           ├─ source-address = broker real IP
     │                                           └─ enforces force-command (if present)
     │
     │◄── stdout / stderr / exit_code ───────────
```

### ④ ProxyJump: one independent certificate per hop

```
  broker               bastion :22                  target :22
  ──────               ───────────                  ──────────
     │                      │                            │
     │  TCP                 │                            │
     │─────────────────────►│                            │
     │  bastion cert:       │  sshd verifies:            │
     │  - principal         │  TrustedUserCAKeys,        │
     │  - no force-cmd      │  principal, TTL,           │
     │  - permit-port-fwd   │  source-address            │
     │                      │                            │
     │  direct-tcpip ────────────────────────────────────►
     │  target cert:                                      │  sshd verifies:
     │  - principal                                       │  TrustedUserCAKeys,
     │  - force-command (one-shot)                        │  principal, TTL,
     │  - source-address = bastion IP                     │  source-address
     │  - no permit-port-fwd                              │  = bastion IP
     │                                                    │
     │◄──────── stdout / stderr / exit_code ──────────────│
```

## Why a custom MCP server

`mcp-ssh-manager` uses the Node library **`ssh2` 1.17**, which **does not support
SSH client certificate authentication** (verified: with key and cert in the agent,
`ssh2` presents only the bare key, never the `ssh-ed25519-cert-v01`). This broker
is its own MCP server, correctly signing and presenting certificates (tested
against OpenSSH `sshd` in `lab/`).

## API Reference

See [`API.md`](API.md) for the full endpoint documentation.

| Service | Endpoint | Auth | Description |
|---|---|---|---|
| Signer | `POST /v1/sign` | mTLS | Request an ephemeral SSH certificate |
| Signer | `GET /v1/hosts` | mTLS | List accessible hosts (filtered by caller groups) |
| Signer | `POST /v1/reload` | mTLS | Hot-reload `signer.json` without restart |
| Broker HTTP | `POST /v1/ssh_run` | mTLS | Execute a one-shot SSH command |
| MCP HTTP | `GET /.well-known/oauth-protected-resource` | None | OAuth2 discovery (RFC 9728) |
| MCP HTTP | Streamable HTTP | OIDC Bearer | MCP tools: `ssh_execute`, `ssh_session_*`, `ssh_list_servers` |

## Code structure

| Path | Purpose |
|------|---------|
| `internal/broker/engine.go` | Core: config + hop chain + execute+audit (ExecOptions: Sudo/SudoUser/PTY) |
| `internal/broker/session.go` | Session registry (pool) + reaper + escalation in sessions |
| `internal/signer/*` | `Signer` interface, `Local`/`Remote`, policy and intent (allow_sudo, allow_pty) |
| `cmd/signer/main.go` | External signing service (HTTP+mTLS) + issuance audit (escalation) |
| `internal/ca/sign.go` | `GenerateEphemeralKey` + `BuildAndSign` (permit-pty, permit-port-forwarding) |
| `internal/ssh/run.go` | Multi-hop dial (`Dial`/`Conn`) + one-shot execution with/without PTY |
| `internal/ssh/shell.go` | Stateful shell: without PTY (`OpenShell`) and with PTY (`OpenShellPTY`) |
| `internal/audit/log.go` | Signed and chained log (`elevation`, `pty` fields) |
| `internal/auth/mtls.go` | mTLS for HTTP frontend + server-only TLS for HTTP+OAuth; caller identity |
| `internal/mcpserver/*` | Shared tool registry (stdio and HTTP) parametrized by caller identity |
| `internal/oauth/verifier.go` | OIDC bearer token validation via JWKS (go-oidc); extracts user and groups |
| `cmd/mcp-broker/main.go` | MCP server (stdio): tools with Sudo/SudoUser/PTY |
| `cmd/mcp-broker-http/main.go` | Remote MCP server (Streamable HTTP + OAuth2/OIDC) with PRM (RFC 9728) |
| `cmd/broker/main.go` | HTTP `POST /v1/ssh_run` frontend (mTLS) with Sudo/SudoUser/PTY |
| `deploy/sshd_config.snippet` | Config to apply on each managed host (PTY + sudoers) |
| `lab/run_mcp_lab.sh` | MCP end-to-end lab |
| `lab/run_lab.sh` | HTTP/mTLS frontend end-to-end lab |

## Register the MCP in Claude Code

```bash
go build -o ~/bin/mcp-broker ./cmd/mcp-broker
```

In `~/.claude.json` (or `claude mcp add`):

```json
"ssh-broker": {
  "type": "stdio",
  "command": "/Users/<you>/bin/mcp-broker",
  "args": ["-config", "/secure/path/config.json"]
}
```

## Register the MCP in OpenCode

```bash
go build -o ~/bin/mcp-broker ./cmd/mcp-broker
```

In `~/.config/opencode/opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "ssh-broker": {
      "type": "local",
      "command": ["/home/<you>/bin/mcp-broker", "-config", "/secure/path/config.json"],
      "enabled": true
    }
  }
}
```

The difference from Claude Code: `type` is `"local"` (not `"stdio"`) and
`command` is an array where the first element is the binary and the rest are
arguments.

## Remote MCP frontend (OAuth2/OIDC)

To expose the broker over the network to multiple users, `cmd/mcp-broker-http`
serves the same tools over **Streamable HTTP** and requires an **OIDC bearer
token**. This aligns with the [MCP authorization spec](https://modelcontextprotocol.io/docs/tutorials/security/authorization),
which reserves OAuth for HTTP transports (for stdio, isolation comes from the
process, not OAuth).

Flow:

1. The MCP client (VS Code, Claude Code, …) connects; the broker responds `401`
   with `WWW-Authenticate` pointing to `/.well-known/oauth-protected-resource`
   (RFC 9728).
2. The client discovers the Authorization Server (issuer) and does **Authorization
   Code + PKCE**.
3. The client retries with `Authorization: Bearer <token>`. The broker validates
   the JWT **locally** against the issuer's JWKS (signature, `iss`, `aud`, `exp`)
   — no round-trip per request, no client_secret.
4. The token identity (`user_claim`, e.g. `preferred_username`) is recorded in the
   audit log. If the token carries `groups_claim`, those groups are **forwarded to
   the signer**, which requires that the requested host shares at least one of the
   user's groups (per-user RBAC, in addition to broker CN mTLS RBAC).

Config (`oauth` block + `resource_url` in the broker config, see
`config.example.json`):

```json
"listen": ":8443",
"server_cert": "pki/broker.crt",
"server_key": "pki/broker.key",
"resource_url": "https://ssh-broker.example.com",
"oauth": {
  "issuer": "https://keycloak.example.com/realms/infra",
  "audience": "https://ssh-broker.example.com",
  "required_scopes": ["mcp:tools"],
  "user_claim": "preferred_username",
  "groups_claim": "groups",
  "max_token_age_seconds": 3600
}
```

```bash
go build -o ~/bin/mcp-broker-http ./cmd/mcp-broker-http
~/bin/mcp-broker-http -config /secure/path/config.json
```

Per-user RBAC only activates when the token carries groups; stdio and mTLS
requests (without user groups) are authorized as before (compatible).

## Hot reload of the signer

The signing service can re-read its `signer.json` without restarting, atomically
replacing the **hosts policy**, `max_ttl_seconds`, and the **CA key**. If the new
config is invalid, the previous state is preserved. `listen`, TLS, and `audit_log`
require a restart (they reopen sockets/files).

Two triggers:

- **`POST /v1/reload`** (mTLS): only CNs listed in `reload_callers` may invoke it
  (others → 403). If `reload_callers` is empty, the HTTP endpoint is disabled.
  Response: `{"status":"ok","hosts":N}`.
- **`SIGHUP`** (`kill -HUP <pid>`): local reload, bypasses the allowlist. Useful
  from `signer.sh`.

All reloads are audited (`reloaded` / `reload-denied` / `reload-failed`).

```bash
# via endpoint (cert of a CN in reload_callers)
curl --cert broker-admin.crt --key broker-admin.key --cacert signer_ca.crt \
     -X POST https://127.0.0.1:9443/v1/reload
# via signal
kill -HUP "$(cat signer.pid)"
```

## Security (v1.4.1)

Twelve hardening controls added in v1.4.1 (MCP/Snyk audit):

| Control | File(s) | Detail |
|---|---|---|
| Session ownership check (C1) | `internal/broker/session.go` | `SessionExec`/`CloseSession` verify the caller is the session owner before operating. |
| HTTP timeouts (A1) | `cmd/signer/main.go`, `cmd/mcp-broker-http/main.go` | `ReadTimeout`, `WriteTimeout` (signer only), `IdleTimeout` on `http.Server`. |
| Payload limit (A2) | `cmd/signer/main.go`, `internal/signer/remote.go` | `MaxBytesReader(64 KiB)` on `/v1/sign`; `LimitReader(1 MiB)` on `remote.go` responses. |
| SSH execution timeout + output limit (A3) | `internal/ssh/run.go`, `internal/ssh/shell.go` | Default timeout 10 min; output capped at 10 MiB; `SIGTERM` on timeout. |
| Audit chain restoration (A4) | `internal/audit/log.go` | On restart, `restoreChain()` recovers `seq`+`prevHash` from the last entry via `bufio.Scanner`. |
| Audit errors visible (M1) | `internal/broker/engine.go`, `cmd/signer/main.go` | `auditLog.Append` errors no longer silenced with `_ =`; logged via `log.Printf`. |
| Active session limit (M2) | `internal/broker/session.go` | `maxSessionsGlobal=200`, `maxSessionsPerCaller=20`. |
| JWT age validation (M3) | `internal/oauth/verifier.go` | `OAuthConfig.MaxTokenAgeSeconds` validates the `iat` claim; recommended 3600 s in production. |
| Newlines rejected in commands (M5) | `internal/broker/session.go` | `SessionExec` rejects commands containing `\n`/`\r`. |
| CA-from-PEM warning (L1) | `internal/ca/sign.go` | `LoadCAFromPEM` emits `[WARN]` at runtime. |
| Audit log rotation (L2) | `internal/audit/log.go` | `maybeRotate()` rotates the file when it exceeds 100 MiB. |
| MCP input pre-validation (L4) | `internal/mcpserver/tools.go` | `validateInput()` caps fields at 64 KiB and rejects null bytes before reaching the engine. |

## Testing

```bash
bash lab/run_signer_lab.sh  # external signing service: broker WITHOUT ca_key + policy + denial
bash lab/run_mcp_lab.sh     # bastion + target (Jump) + MCP scenario (one-shot, exec, shell)
bash lab/run_lab.sh         # HTTP/mTLS frontend
go test ./...               # cert build, signer policy (authz/TTL/sudo/PTY), hop resolution
```

## Production roadmap

- Back the CA key with a `crypto.Signer` from HSM/KMS/Secure Enclave (seam:
  `ca.LoadCAFromPEM` → `ssh.Signer`).
- Rate limiting per broker CN in the signing service (anti-DoS/abuse limit).
- One CA per host group (selection by `host` in config).
- KRL for emergency revocation by serial (see `deploy/sshd_config.snippet`).
- Rotation/segregation of audit key; ship the log to WORM storage or external
  service.
- End-to-end lab scenario for sudo + PTY (`lab/run_mcp_lab.sh`).
