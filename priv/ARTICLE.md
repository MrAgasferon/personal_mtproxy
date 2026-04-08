# Personal MTProto Proxies: Give Every User Their Own Secret Domain

## Why This Matters

While we all are waiting for the latest Telegram update to roll-out the upgraded Fake-TLS
implementation, let me introduce you to my 2018 MTProto proxy implementation which becomes
actual again and tell you about one of its unique features.

MTProto proxy is the standard solution for Telegram users in countries with
internet censorship. Most deployments work like this: an operator sets up a
proxy, publishes one link, and thousands of people use it. Simple, but this
model has real limitations:

- **No access control.** Anyone with the link can use your server indefinitely.
  You cannot revoke a specific user's access without rotating the shared secret
  and breaking everyone else's link.
- **No per-user analytics.** You can see total connection counts, but you cannot
  tell which users are active, which ones share their link with fifty friends, or
  which ones you are paying bandwidth for.
- **No monetization.** If you want to charge for access, there is no natural
  handle — the secret is the same for everyone, so there is nothing to tie to
  a subscription.

What if each user had their own unique secret that granted access only to them?
You could sell subscriptions, revoke individual users, enforce fair-use limits,
and track per-user activity — all without running custom bots or patching the
proxy binary.

In fairness, [mtprotoproxy](https://github.com/alexbers/mtprotoproxy) (the
popular Python implementation) does support multiple users, each with their own
secret. However, its approach does not scale: on each incoming connection it
tries to decrypt the handshake with every configured secret one by one until one
fits. In practice this means no more than ~100 users before the per-connection
CPU cost becomes noticeable.

`mtproto_proxy` takes a different approach: it uses a single shared base secret
per listener port, validates each connection in O(1), and delegates
per-user access control to a runtime-configurable **policy system**. In this
article we will explain how it works, show the simplest way to use it from the
command line, and then walk through a complete demo application —
[`personal_mtproxy`](https://github.com/seriyps/personal_mtproxy) — that wires
together `mtproto_proxy`, Cowboy web-server, and a persistent store into a self-hosted
personal proxy registration portal.

The article assumes you are comfortable with systems programming and have a brief understanding of
what MTProto proxy is. The later
sections include Erlang code; basic familiarity with the language helps, but we
explain the important idioms as they appear.

---

## Why Erlang for a Proxy?

Before diving into the feature, it is worth understanding why `mtproto_proxy`
is written in Erlang and why that is a good choice for this use case.

**Concurrency is in the DNA.** Erlang was designed at Ericsson in 1986 for
telephone switches — the same problem domain as a proxy: millions of long-lived
connections, no downtime, faults in one call must not affect others. The actor
model is not a library bolted on top; it is the execution model of the VM.

**Each connection is an isolated process.** A crash in one client's connection
handler cannot corrupt another's state. OTP supervisor trees restart failed
components automatically. The system degrades gracefully under load rather than
crashing hard. Add to that almost unique feature of Erlang VM - preemptive scheduling: actors
are force-preempted by VM after executing certain amount of code, similar to how Linux kernel
preempts processes, so no single client can occupy a whole core for a long time.

**Scales to all CPUs automatically.** The BEAM scheduler runs one OS thread per
core and distributes lightweight processes (starting at ~2 kB of memory each)
across them. No thread pools, no event loops to manage manually.

**Not CPU-bound.** A proxy's real work is I/O and byte-routing. The only
significant CPU cost is AES-CTR encryption, handled by native built-in `crypto`
application (OpenSSL under the hood). Everything else is
message passing between processes.

**Bit syntax makes protocol parsing trivial and safe.** Binary pattern matching
is a first-class language feature — you can destructure a raw TLS ClientHello
directly in a function head, with field widths, endianness, and length-prefixed
sub-fields, all in one expression:

```erlang
parse_client_hello(
  <<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsFrameLen:16,
    ?TLS_TAG_CLIENT_HELLO, HelloLen:24, ?TLS_12_VERSION,
    Random:32/binary,
    SessIdLen,       SessId:SessIdLen/binary,
    CipherSuitesLen:16, CipherSuites:CipherSuitesLen/binary,
    CompMethodsLen,  CompMethods:CompMethodsLen/binary,
    ExtensionsLen:16, Extensions:ExtensionsLen/binary>>
) when TlsFrameLen >= 512, HelloLen >= 508 -> ...
```

That is the actual function clause in `mtp_fake_tls.erl`.
Misaligned reads are impossible; the pattern either matches the entire binary or it does not.

**Live system introspection.** Erlang ships with a built-in distributed shell.
You can attach a remote console to a running production node — no agent, no
debug build — and inspect process state, call functions, trace messages, monkey-patch and
update configuration while the proxy is serving real traffic:

```bash
mtp_proxy remote_console
# Now you are inside the live VM:
(mtp_proxy@host)> mtp_policy_table:table_size(personal_domains).
```

**Hot code upgrades.** OTP's `code_change/3` callback and `sys.config` reload
let you update running business logic code, in-memory state and configuration at runtime. Existing client
connections stay alive across the upgrade — essential for a production proxy
where restarting disconnects thousands of users.

![Architecture](architecture.svg)

---

## SNI, Fake-TLS, and How Secrets Encode Domains

### What is SNI?

**Server Name Indication (SNI)** is a TLS extension that lets a client tell the
server which hostname it is trying to reach, before the TLS handshake is
complete. This is how a single IP address can serve TLS certificates for many
domains: the server reads the SNI field from the ClientHello, picks the right
certificate, and proceeds.

In real TLS 1.3, the ClientHello travels in plaintext (only later messages are
encrypted), so SNI is visible to any observer on the path — including DPI
systems. That is why fake-TLS is so effective: it mimics the TLS 1.3 ClientHello
byte-for-byte, including a valid SNI field pointing to a legitimate-looking
domain, while carrying the MTProto handshake data hidden inside fields the DPI
probe cannot validate without the secret key.

### The fake-TLS secret format

The proxy secret for fake-TLS encodes both an authentication token and the SNI
domain the client will claim:

```
0xEE  |  <16 random bytes (base token)>  |  <SNI domain as UTF-8>
```

As a hex string (for `t.me/proxy` links):

```
ee<32 hex chars of the 16-byte token><hex-encoded SNI domain>
```

Base64 encoding also exists, but less popular due to bugs in telegram clients.

The proxy validates each incoming ClientHello by computing an HMAC over the
packet using its single shared base secret (one per listener port). If the
digest checks out, the SNI domain is extracted from the ClientHello's SNI
extension and passed to the policy engine as `tls_domain`. All users share the
same base secret; what makes each personal link unique is the SNI domain baked
into it, not a separate per-user cryptographic key.

To build or decode such a secret without writing code, use
[mtpgen.html](https://seriyps.com/mtpgen.html).

---

## The Policy System

`mtproto_proxy` evaluates a **policy** — an ordered list of rules — for every
incoming connection before forwarding it to Telegram. If any rule fails, the
connection is rejected. Think of it as `iptables` rules for proxy connections:
rules are checked top-to-bottom, and the first failure drops the connection.

The available rule types are:

| Rule | Description |
|------|-------------|
| `{in_table, Key, Table}` | The value of `Key` must be present in `Table` |
| `{not_in_table, Key, Table}` | The value of `Key` must NOT be present in `Table` |
| `{max_connections, [Key, ...], N}` | Active connections sharing the same values of the listed keys must not exceed `N` |

The available **keys** that can be extracted from a connection:

| Key | Value |
|-----|-------|
| `tls_domain` | SNI domain encoded in the fake-TLS secret |
| `port_name` | Name of the proxy socket listener (from `ports` config) |
| `client_ipv4` | Client IPv4 address |
| `client_ipv6` | Client IPv6 address |
| `{client_ipv4_subnet, Mask}` | Client IPv4 address masked to `Mask` bits |
| `{client_ipv6_subnet, Mask}` | Client IPv6 address masked to `Mask` bits |

**Tables** are named in-memory hash tables. They survive config reloads but are
lost on restart (unless you repopulate them — which is exactly what our demo
app does on startup). In the `iptables` analogy those can be `ipset` sets.

### Personal proxy policy

The policy for personal proxies is two rules:

```erlang
{policy, [
  {in_table, tls_domain, personal_domains},
  {max_connections, [tls_domain], 30}
]}
```

1. **`{in_table, tls_domain, personal_domains}`** — the SNI domain encoded in
   the client's secret must exist in the `personal_domains` table. An
   unregistered domain → connection rejected.

2. **`{max_connections, [tls_domain], 30}`** — at most 30 simultaneous
   connections may share the same SNI domain. This limits credential sharing:
   even if a user publishes their personal link publicly, at most 30 connections can
   be made at once on that domain (typical Telegram client opens up to 8 connections).

Combined with `{allowed_protocols, [mtp_fake_tls]}` (only fake-TLS accepted),
every client must present a valid, registered personal SNI domain or be rejected.

If we want to limit the number of connections per-IP address, add two more rules (or one if you
don't use IPv6):

```erlang
  {max_connections, [client_ipv4], 30},
  {max_connections, [client_ipv6], 30}
```

---

## Approach 1: Vanilla Personal Proxy via `eval`

No code changes required. [Install `mtproto_proxy`](https://github.com/seriyps/mtproto_proxy#how-to-install---one-line-interactive-installer),
add the policy to `sys.config`, then add SNI domains to the table with a shell Erlang RPC command.

### sys.config

```erlang
{mtproto_proxy, [
  {ports, [
    #{name      => mtp_handler,
      listen_ip => "0.0.0.0",
      port      => 443,
      secret    => <<"d0d6e111bada5511fcce9584deadbeef">>,
      tag       => <<"dcbe8f1493fa4cd9ab300891c0b5b326">>}
  ]},
  {allowed_protocols, [mtp_fake_tls]},
  {policy, [
    {in_table, tls_domain, personal_domains},
    {max_connections, [tls_domain], 100}
  ]}
]}
```

### Registering a user

Use [mtpgen.html](https://seriyps.com/mtpgen.html) to build the personal link
for `alice42.example.com`, then add the SNI domain to the live whitelist:

```bash
mtp_proxy eval '
  mtp_policy_table:add(personal_domains, tls_domain, "alice42.example.com").'
```

That's it — the domain is active immediately, no restart required.

### Pros and cons

✅ Zero code to write. Works with any existing `mtproto_proxy` installation.

❌ **The table is lost on restart.** You must re-add all domains after every
restart — typically via a `systemd` `ExecStartPost` script that replays a list.

❌ **No easy to use UI or API.** the `eval` command to add subdomains to allow-list is not
very efficient.

---

## Approach 2: Embed `mtproto_proxy` in your own Erlang app

To address both cons, we built a small sample demo application that:

1. Wraps `mtproto_proxy` as a library dependency.
2. Adds a Cowboy HTTPS server with a registration UI.
3. Persists registered SNI domains to disk and restores them into the policy
   table on every restart automatically.

The full source is at: https://github.com/seriyps/personal_mtproxy

The demo instance is currently running at https://demo.personal-mtp.online/admin.html

![WEB UI](ui-screenshot.png)

### Architecture and domain fronting

```
Internet (port 443, IPv4 + IPv6)
  │
  ▼
mtproto_proxy  (socket listeners)
  │
  ├── fake-TLS handshake OK (valid secret, SNI domain in whitelist)
  │     └── policy: in_table + max_connections → forward to Telegram
  │
  └── fake-TLS handshake FAILS (SNI mismatch or invalid digest - eg, browser or DPI probe)
        └── domain_fronting → 127.0.0.1:1443
                                │
                                ▼
                          Cowboy HTTPS (registration UI)
                            GET  /          → index.html
                            POST /api/proxies → JSON
```

**Domain fronting** is the mechanism that makes proxy look like a legitimate HTTPS website
for the web-browsers and DPI-probes, but serve as MTProto proxy for those who know the proxy secret.

For this demo we serve the registration UI on the same port 443 as the MTP proxy — zero extra
infrastructure, a single binary to deploy and a good example to show how fronting works.
In a real production setup you would front an unrelated, innocent-looking public website (e.g. a
corporate landing page or blog or add it to round-robin DNS of a real website to pump real user
traffic through it), and serve the registration UI and API on a separate internal port or a
completely different machine. The `personal_mtproxy` demo supports both modes via
the `web_listen_ip` / `web_listen_port` config options.

When a connection arrives and the fake-TLS handshake fails — because the client is a
real browser or a DPI probe — `mtproto_proxy` does not close the
connection. Instead it forwards the raw TCP stream to the configured
`domain_fronting` target, which is our WEB UI server.

The handshake fails due to a **cryptographic digest mismatch**: the fake-TLS
secret embeds an HMAC that the proxy validates against its own secret key.
A real browser's ClientHello contains no such digest, so the check always fails
and the connection is forwarded to the "fronting" host.

In order to front an entirely unrelated site (e.g. `microsoft.com`), and serve the registration UI
on a separate internal port default config should be changed:

```erlang
%% Front microsoft.com; serve admin UI / API on localhost:8443
{mtproto_proxy, [
  ...
  {domain_fronting, "microsoft.com:443"},
  ...
]},
{personal_mtproxy, [
  ...
  {web_listen_ip,   "127.0.0.1"},  %% admin UI on localhost only
  {web_listen_port, 8443},
  ...
]}
```

### Persistence with DETS

We need to store the list of registered SNI domains so it survives restarts.
The simplest approach would be a plain text file — one domain per line — read
on startup and appended on each registration. For this demo we chose DETS instead because it
is Erlang's built-in disk-backed hash table: it provides atomic inserts, crash
recovery, and `O(1)` lookups with no external process or daemon required. It is
part of the standard library with no extra dependencies.

In practice, this storage is a detail. The `pm_registry` gen_server owns the
DETS file; swapping it for PostgreSQL, Redis, or a plain file requires changing
only that module.

On startup, the registry replays all stored domains into the live policy table:

```erlang
ok = dets:foldl(
  fun({Subdomain, _Email, _Timestamp}, ok) ->
          mtp_policy_table:add(personal_domains, tls_domain, Subdomain)
  end,
  ok, DetsRef),
```

After `init/1` returns, the whitelist is identical to what it was before the
last shutdown — zero manual intervention.

### Registration flow

When a user clicks "Get my proxy", the browser sends a `POST /api/proxies`
with an optional email field. The web handler reads the body, parses the
URL-encoded form, and calls `pm_registry:register/1`.

The registry generates a 5-character alphabetic slug (`[a-z]{5}`, ~11.8 million
combinations), checks DETS for collision (retries up to 5 times),
writes the record to DETS, and adds the SNI domain to the live policy table.
It then returns the subdomain, port, and base secret to the handler.

The web handler constructs the proxy secret as:
`"ee" ++ base_secret_hex ++ hex(subdomain)`, builds both a `t.me/proxy` and a
`tg://proxy` link, and returns JSON.

Static files (`index.html`) are served by Cowboy's built-in
`cowboy_static` handler — no templating engine or extra code needed.

### The full sys.config

```erlang
[
  {mtproto_proxy, [
    {ports, [
      #{name      => mtp_ipv4,
        listen_ip => "0.0.0.0",
        port      => 443,
        secret    => <<"d0d6e111bada5511fcce9584deadbeef">>,
        tag       => <<"dcbe8f1493fa4cd9ab300891c0b5b326">>},
      #{name      => mtp_ipv6,
        listen_ip => "::",
        port      => 443,
        secret    => <<"d0d6e111bada5511fcce9584deadbeef">>,
        tag       => <<"dcbe8f1493fa4cd9ab300891c0b5b326">>}
    ]},
    {allowed_protocols, [mtp_fake_tls]},
    {domain_fronting, "127.0.0.1:1443"},
    {policy, [
      {in_table, tls_domain, personal_domains},
      {max_connections, [tls_domain], 100}
    ]}
  ]},
  {personal_mtproxy, [
    %% skipping 'web_listen_ip' so it uses 'domain_fronting' parameter instead
    {base_domain, "demo.personal-mtp.online"},
    {dets_file,   "/var/lib/personal_mtproxy/proxies.dets"},
    {ssl_cert,    "/etc/letsencrypt/live/demo.personal-mtp.online/fullchain.pem"},
    {ssl_key,     "/etc/letsencrypt/live/demo.personal-mtp.online/privkey.pem"}
  ]}
].
```

---

## TLS Certificate

In our examples we use 3-level domain for UI and 4-level domains for personal secrets,
but we can use any levels, say serve UI on 2nd level `personal-mtp.online` and personal on
3rd level `alice42.personal-mtp.online`.

### Simple setup (single-domain, no wildcard)

The registration UI is served at `demo.personal-mtp.online` — the 3rd-level
base domain. A standard DV certificate obtained via certbot is sufficient:

```bash
certbot certonly --standalone -d demo.personal-mtp.online
```

Personal SNI domains are 4th-level (`alice42.demo.personal-mtp.online`). When a
Telegram client connects to the proxy using a 4th-level SNI domain, the MTP
handshake completes **before TLS is ever shown to the client**. The fake-TLS
ClientHello is validated against the secret, not against a real TLS certificate.
The subdomain mismatch is invisible to the Telegram app.

It is, however, visible to two things:

- **Real browsers** — navigating to `https://alice42.demo.personal-mtp.online`
  will show a certificate warning. For a proxy, this is acceptable: users click
  a `tg://proxy` deep link, they never visit that URL in a browser.
- **Active DPI probes** that MAY complete a real TLS handshake to check the
  certificate. A mismatch between the SNI hostname and the certificate SAN is an
  anomaly that a sophisticated probe could flag.

### Wildcard certificate

A wildcard cert eliminates both concerns. It requires the DNS-01 challenge
because the CA must verify you control `*.demo.personal-mtp.online`:

```bash
certbot certonly --manual --preferred-challenges dns \
  -d "*.demo.personal-mtp.online" \
  -d "demo.personal-mtp.online"
```

Certbot will ask you to create a `_acme-challenge.demo.personal-mtp.online`
TXT record in your DNS. After adding it, press Enter and certbot validates and
issues the cert.

---

## Running the Demo Locally

On Linux or MacOS

```bash
git clone https://github.com/seriyps/personal_mtproxy
cd personal_mtproxy
make dev   # generates self-signed cert, updates /etc/hosts, starts rebar3 shell
```

Open `https://demo.personal-mtp.test:1443/` in your browser (accept the
self-signed cert warning). Enter an optional email, click **Get my proxy** —
you receive a personal `t.me/proxy` link and a `tg://proxy` deep link - you can use them
straight away even on localhost with Telegram Desktop!

The MTP proxy itself listens on port 1433 in local mode (no root required).

Cleanup:

```bash
make clean   # removes /etc/hosts entry, self-signed cert, compiled beams
```

Production Deployment you may find in demo app's README.

## Ideas for Extension

The demo is intentionally minimal. Here are natural next steps:

- **Checkout and payments.** Implement in Erlang, or use APIs Erlang demo app provides. On a
  successful payment event, call `pm_registry:register/1` or `POST /api/proxies` and email
  the link to the user.
- **Per-user connection counters.** `mtp_policy_counter` tracks connection counts
  in memory; expose them via a simple admin API endpoint for monitoring.
- **Revocation** is already implemented: `DELETE /api/proxies?subdomain=<sub>` removes a
  SNI domain from the persistent store and from the live policy table, immediately cutting
  off that user's access. Returns `404` if the subdomain was not registered. The UI exposes
  it as a "Revoke" button shown right after registration.
- **Expiry.** The registration timestamp is stored alongside each subdomain.
  A scheduled timer in `pm_registry` can evict SNI domains older than N days
  automatically.
- **Separate admin panel.** Instead of combining the fronted site and the
  registration UI, serve the admin panel on a local-only or protected port and front an
  unrelated public website on 443.
- **Per-user independent secrets.** Currently all users share the same base
  secret at the port level — what makes each link personal is the SNI domain,
  not a separate cryptographic key. A natural extension for proxy that only serves Fake-TLS,
  would be to generate a `SNI <-> personal_secret_key` mapping and give each
  registered subdomain its own 16-byte secret. This would require a small change to
  `mtproto_proxy` itself: instead of validating the HMAC with a single known
  secret, the proxy would need to extract the SNI domain from the ClientHello
  first, look up the corresponding per-user secret, and then validate. It is possible because SNI
  is transferred in plaintext.

---

## Conclusion

`mtproto_proxy`'s policy system makes it uniquely capable among open-source
MTProto proxy implementations: it is the only one that lets you issue personal
proxy secrets per user, enforce per-user connection limits, and persist the
whitelist across restarts — all without patching the proxy source.

The `personal_mtproxy` demo shows that wiring this into a self-hosted
registration portal requires fewer than 300 lines of Erlang. The language
choices — OTP application structure, gen_server for serialized state access,
DETS for dependency-free persistence, Cowboy for HTTPS — all pull from the
standard Erlang/OTP toolkit with minimal external dependencies.

The full source https://github.com/seriyps/personal_mtproxy
The live demo https://demo.personal-mtp.online/admin.html

---

## Update — 2026-04-08: Multi-vhost support

The config format has changed to support multiple base domains on a single node and port. Instead of three flat keys, configure a `vhosts` list:

```erlang
{personal_mtproxy, [
  {vhosts, [
    #{domain   => "demo.personal-mtp.online",
      ssl_cert => "/var/lib/personal_mtproxy/demo.personal-mtp.online/fullchain.pem",
      ssl_key  => "/var/lib/personal_mtproxy/demo.personal-mtp.online/privkey.pem"},
    #{domain   => "prod.personal-mtp.online",
      ssl_cert => "/var/lib/personal_mtproxy/prod.personal-mtp.online/fullchain.pem",
      ssl_key  => "/var/lib/personal_mtproxy/prod.personal-mtp.online/privkey.pem"}
  ]},
  {dets_file, "/var/lib/personal_mtproxy/proxies.dets"},
  ...
]}
```

Each vhost needs its own wildcard TLS certificate. Cert files are now stored in per-domain subdirectories (`DATADIR/<domain>/`) instead of flat under `DATADIR/`.

**The old `{base_domain, ssl_cert, ssl_key}` keys still work** — the app accepts them with a deprecation warning, so single-domain installs keep running without any immediate changes.

### Migrating an existing install

```bash
# 1. Pull the new code
git pull

# 2. Update sys.config: replace the three legacy keys with the vhosts list,
#    pointing ssl_cert/ssl_key at the new per-domain paths:
#      /var/lib/personal_mtproxy/<domain>/fullchain.pem
#      /var/lib/personal_mtproxy/<domain>/privkey.pem
$EDITOR config/sys.config

# 3. Build and install the new release (creates per-domain cert dirs, copies certs)
make && sudo make install

# 4. Clean up the old flat cert files and symlink
sudo make migrate-vhosts-certs

# 5. Push the updated config and reload
make update-sysconfig && sudo systemctl reload personal_mtproxy
```

`migrate-vhosts-certs` is safe to run after `make install` — the service is
already working with the new layout at that point; the target just removes the
leftover flat `fullchain.pem`, `privkey.pem`, and `cert-lineage` symlink from
`DATADIR/`. It is also idempotent: running it again on an already-migrated
install is a no-op.
