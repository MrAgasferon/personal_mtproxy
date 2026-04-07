# AGENTS.md

## Project Overview

`personal_mtproxy` is a self-contained demo Erlang/OTP application that embeds
[`mtproto_proxy`](https://github.com/seriyps/mtproto_proxy) as a library dependency and adds:

- A **Cowboy HTTPS registration UI and API** where users enter an optional email and click "Get my proxy"
  to receive a personal fake-TLS MTProto proxy link tied to a unique 4th-level subdomain.
- **DETS persistence**: registered subdomains survive restarts and are replayed into the
  `mtproto_proxy` policy table on startup.
- **Domain fronting**: the same port 443 that serves MTP traffic forwards non-MTP connections
  (browsers, DPI probes) to Cowboy's HTTPS UI — the proxy looks like a normal HTTPS site.

Live demo: https://demo.personal-mtp.online/admin.html  
Article: https://github.com/seriyps/personal_mtproxy/blob/master/priv/ARTICLE.md
RU article: https://habr.com/ru/articles/1019648/

---

## Repository Layout

```
src/
  personal_mtproxy.app.src   — OTP application descriptor, config defaults
  personal_mtproxy_app.erl   — application start: validate ports, start Cowboy, domain-fronting setup
  personal_mtproxy_sup.erl   — one-for-one supervisor (starts pm_registry)
  pm_registry.erl            — gen_server: DETS owner, slug generation, register/revoke/list
  pm_web_handler.erl         — Cowboy handler: POST /api/proxies, DELETE /api/proxies
config/
  sys.config.example         — production config template (copy to sys.config before building)
  vm.args.example
  local.sys.config           — dev config (self-signed certs, port 2443)
  personal-mtproxy.service   — systemd unit (AmbientCapabilities for port 443)
  certbot-deploy.sh          — certbot renewal hook, installed by `make install`
priv/
  htdocs/
    index.html               — landing page (sensitive keywords HTML-entity-encoded for DPI evasion)
    admin.html               — registration UI (AJAX, revoke button)
  ARTICLE.md                 — English article (published)
  architecture.svg           — mtproto_proxy architecture diagram
```

---

## Key Source Modules

### `personal_mtproxy_app.erl`

- Validates that all `{mtproto_proxy, ports}` entries agree on `port` and `secret` (crashes with
  a clear message otherwise).
- Starts Cowboy SSL. Bind address is determined by:
  - `{personal_mtproxy, web_listen_ip}` + `{personal_mtproxy, web_listen_port}` if set → `explicit` mode
  - Otherwise parses `{mtproto_proxy, domain_fronting}` (e.g. `"127.0.0.1:1443"`) → `fronting` mode
- In `fronting` mode: adds `base_domain` to the `personal_domains` policy table at startup so that
  DPI probes hitting the base domain are correctly forwarded to Cowboy (not dropped). This is
  intentional — see "Domain fronting design note" below.
- Routes: `/` → `index.html`, `/admin.html` → `admin.html`, `/api/proxies` → `pm_web_handler`,
  `/static/[...]` → `priv/htdocs/` directory.

### `pm_registry.erl`

- Gen_server; owns the DETS file (table name `pm_subdomains`).
- `init/1`: opens DETS, replays all stored subdomains into `mtp_policy_table` via
  `mtp_policy_table:add(personal_domains, tls_domain, Subdomain)`.
- `register(Email)` → `{ok, Subdomain, Port, BaseSecret}`:
  - Generates a 5-char `[a-z]{5}` slug (~11.8M combinations), checks DETS for collision, retries up to 5 times.
  - Subdomain = `<slug>.<base_domain>` (binary).
  - Inserts `{Subdomain, Email, erlang:system_time(second)}` into DETS.
  - Calls `mtp_policy_table:add(personal_domains, tls_domain, Subdomain)`.
  - Reads `port` and `secret` live from `{mtproto_proxy, ports}` (first entry).
- `revoke(Subdomain)` → `ok | {error, not_found}`:
  - Looks up DETS first; returns `{error, not_found}` if missing.
  - Calls `mtp_policy_table:del(personal_domains, tls_domain, Subdomain)`.
- `list()` → list of `{Subdomain, Email, Timestamp}` tuples.

### `pm_web_handler.erl`

- `POST /api/proxies` (body: URL-encoded form, optional `email` field):
  - Calls `pm_registry:register(Email)`.
  - Builds fake-TLS secret: `<<"ee">> ++ hex(BaseSecret) ++ hex(Subdomain)`.
  - Builds `t.me/proxy` and `tg://proxy` links using `uri_string:compose_query/1`.
  - **Server hostname in link = full subdomain** (e.g. `aqfmc.demo.personal-mtp.online`), not base domain.
  - Returns JSON: `{subdomain, link, tg_link}`.
- `DELETE /api/proxies?subdomain=<sub>`:
  - Returns 200 `{ok: true}` or 404 `{error: "subdomain not found"}`.

---

## Configuration

All config is in `config/sys.config` (copy from `sys.config.example`).

```erlang
{mtproto_proxy, [
  {ports, [
    #{name => mtp_ipv4, listen_ip => "0.0.0.0", port => 443,
      secret => <<"HEX_SECRET">>, tag => <<"CHANNEL_TAG">>},
    #{name => mtp_ipv6, listen_ip => "::",      port => 443,
      secret => <<"HEX_SECRET">>, tag => <<"CHANNEL_TAG">>}
  ]},
  {allowed_protocols, [mtp_fake_tls]},
  {domain_fronting, "127.0.0.1:1443"},   %% Cowboy bind addr when web_listen_ip not set
  {policy, [
    {in_table, tls_domain, personal_domains},
    {max_connections, [tls_domain], 100}
  ]}
]},
{personal_mtproxy, [
  {base_domain, "demo.personal-mtp.online"},
  {dets_file,   "/var/lib/personal_mtproxy/proxies.dets"},
  {ssl_cert,    "/var/lib/personal_mtproxy/fullchain.pem"},  %% copied by certbot hook
  {ssl_key,     "/var/lib/personal_mtproxy/privkey.pem"},    %% copied by certbot hook
  %% Optional: bind Cowboy explicitly instead of inheriting domain_fronting
  %% {web_listen_ip,   "127.0.0.1"},
  %% {web_listen_port, 8443}
]}
```

`proxy_port` and `base_secret` are **not** duplicated in `personal_mtproxy` config — `pm_registry`
reads them live from `{mtproto_proxy, ports}` on each registration call.

---

## Build and Run

```bash
# Dev (self-signed cert, /etc/hosts entry, port 2443)
make dev

# Production release
cp config/sys.config.example config/sys.config
$EDITOR config/sys.config
make

# Install (creates system user, copies release to /opt, installs systemd unit + certbot hook)
sudo make install
sudo systemctl enable --now personal_mtproxy

# Reload config without restart
make update-sysconfig && systemctl reload personal_mtproxy
```

---

## Dependencies

| Dep | Version | Why |
|-----|---------|-----|
| `mtproto_proxy` | git master | embedded proxy library |
| `ranch` | 2.2.0 | pinned explicitly to override Cowboy's transitive `1.8.0` dep |
| `cowboy` | 2.12.0 | HTTPS UI server |
| `jsx` | 3.1.0 | JSON encoding for API responses |
| `redbug` | latest | production tracing (included in release) |

Ranch 2.2.0 is pinned in `rebar.config` because `mtproto_proxy` uses the Ranch 2.x map-based
API but its own `rebar.config` only lists `ranch 1.7.0`; without the pin Cowboy's transitive
dep would downgrade Ranch.

---

## TLS Certificate and Permissions

Let's Encrypt private keys are `rw------- root:root` by default — the `personal_mtproxy` service
user cannot read them.

`make install`:
1. Reads `base_domain` from `config/sys.config`.
2. Creates `/var/lib/personal_mtproxy/cert-lineage` → symlink to `/etc/letsencrypt/live/<domain>`.
3. Installs `config/certbot-deploy.sh` → `/etc/letsencrypt/renewal-hooks/deploy/personal_mtproxy.sh`.
4. If cert already exists, runs the hook immediately to copy files to `/var/lib/personal_mtproxy/`.

The hook (`config/certbot-deploy.sh`) is domain-agnostic: it reads the target domain from the
`cert-lineage` symlink, so it works correctly even when multiple certs exist on the same server.
It copies `privkey.pem` (mode 600) and `fullchain.pem` (mode 644), both owned
`personal_mtproxy:personal_mtproxy`, and runs `systemctl reload-or-restart personal_mtproxy`.

`ssl_cert` and `ssl_key` in `sys.config.example` point to `/var/lib/personal_mtproxy/*.pem`
(the copied paths), **not** directly to `/etc/letsencrypt/live/`.

---

## DNS Setup

Two records required (both pointing to the same server for single-server deployments):

| Name | Type |
|------|------|
| `proxy.example.com` | A |
| `*.proxy.example.com` | A |

Proxy links use the **full subdomain** (`aqfmc.proxy.example.com`) as the server hostname.
This allows future per-user smart-DNS routing: point specific subdomains to different servers
via more specific A records without any proxy code changes.

---

## Domain Fronting Design Note

`check_front_policy` in `mtp_handler.erl` applies the same `in_table` policy rules to both
MTP connections and domain-fronted connections (intentional: DPI probes must get consistent
treatment). This means the base domain (`demo.personal-mtp.online`) must be in the
`personal_domains` table for Cowboy to be reachable via fronting.

`personal_mtproxy_app.erl` adds the base domain to the table at startup, but **only in
`fronting` mode** (i.e. when `web_listen_ip` is not set). Side-effect: someone with knowledge
of the base secret could connect using `demo.personal-mtp.online` as SNI without registering.
This is acceptable for the demo; in production you would serve the UI on a separate port
(`web_listen_ip`/`web_listen_port`) and front an unrelated public site.

---

## Live Node Introspection

```bash
# Attach to running node
/opt/personal_mtproxy/bin/personal_mtproxy remote_console

# Or run one-off expressions
/opt/personal_mtproxy/bin/personal_mtproxy eval 'pm_registry:list().'
/opt/personal_mtproxy/bin/personal_mtproxy eval \
  'mtp_policy_table:exists(personal_domains, <<"alice42.demo.personal-mtp.online">>).'
```

Note: `mtp_policy_table:exists/2` takes `(TableName, Value)` — no `key_type` argument.

---

## Reference

- `mtproto_proxy` source: `../mtproto_proxy/` (git: https://github.com/seriyps/mtproto_proxy)
- `mtp_policy_table` API: `add(Table, tls_domain, Value)`, `del(Table, tls_domain, Value)`,
  `exists(Table, Value)`, `table_size(Table)`, `flush(Table)`
- `mtp_fake_tls` secret format: `0xEE | base_secret (16 bytes) | sni_domain (UTF-8)`,
  as hex: `ee<32 hex><hex(sni)>`
- Link generator: https://seriyps.com/mtpgen.html
