# Self-hosting OspreyProxy

This guide is for operators who run their own copy of `OspreyProxy` instead of sending lookups to the public backend at
`https://api.osprey.ac`. It covers the assumptions the server already makes about its environment, the multi-tenant
authentication added for MSP use, and the day-to-day operations of keys, metrics, and the scan store.

## What OspreyProxy is

`OspreyProxy` is the Java and Spring Boot backend the Osprey browser extension calls to run its threat lookups. The
extension sends each URL to `POST /{providerName}`, one request per enabled provider, and the proxy forwards the lookup
upstream, applies caching, coalescing, circuit breaking, and rate limits, and returns a verdict. A separate public
endpoint, `POST /check`, powers the scanner on the website and is protected by its own CORS rules and a Cloudflare
Turnstile captcha. A read-only `GET /result` serves stored scan results to the same single web origin.

## Network assumptions baked into the defaults

The shipped `application.properties` assumes a specific deployment shape. Read this before you expose the service.

### Nginx is the only trusted proxy, and it sets X-Real-IP

The proxy binds to `127.0.0.1` and does not trust `X-Forwarded-*` headers. It reads the client IP from a single
`X-Real-IP` header, which it assumes a trusted reverse proxy in front of it sets. Rate limiting and abuse limiting are
keyed off that hashed IP, so if you let clients reach the service directly, or if your front end forwards a
client-supplied `X-Real-IP`, an attacker can forge the value and defeat the per-IP limits.

Run Nginx (or an equivalent) in front of the proxy, terminate TLS there, and set the header from the real connection:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header X-Real-IP $remote_addr;
    # Do not pass through a client-supplied X-Real-IP or X-Forwarded-For.
    proxy_set_header X-Forwarded-For "";
}
```

Do not proxy `/actuator` from Nginx. See the metrics section below.

### The scan store is a local SQLite file

When `osprey.store.enabled=true`, `/check` writes each aggregate verdict to a local SQLite database at
`osprey.store.path` (default `/var/lib/osprey/scans.db`). The directory must exist and be writable by the service user.
The store is a single file in WAL mode, so a backup is a file copy. If you do not need the public scanner or its result
cache, set `osprey.store.enabled=false` and no database beans are created.

### Health and Prometheus are on an internal-only port

Actuator exposes only `/actuator/health` and `/actuator/prometheus`, and it binds them to `127.0.0.1` on port `9090`,
separate from the main service port. This management port is not meant to be public. Scrape it from Prometheus over the
internal network or an SSH tunnel, and do not let Nginx forward it. Because it runs on a separate connector, the tenant
authentication filter described below does not apply to it, which is intended: your monitoring reaches health and
metrics without a tenant key.

## Multi-tenant authentication

An MSP that serves several client organizations from one self-hosted proxy needs to authenticate each client, keep one
client's traffic from exhausting another's rate budget, and see per-client usage. That is what the tenant layer
provides. It is off by default, so the public deployment is unaffected. When you enable it, every extension-facing
`POST /{providerName}` request must carry a valid per-tenant API key.
`/check` and `/result` are never affected and keep their existing protection.

### Enabling it

Set these in `application.properties` (or as environment overrides):

```properties
osprey.tenant.auth.enabled=true
osprey.tenant.auth.header=X-Osprey-Tenant-Key
osprey.tenant.store.path=/etc/osprey/tenants.properties
```

With `osprey.tenant.auth.enabled=true` and no reachable store, or a store with no keys, every extension request is
rejected with `401`. This is deliberate: enabling authentication without keys fails closed rather than open. The startup
log states plainly how many tenants loaded.

### The tenant key store

The store is a properties file kept outside the repository. Give it mode `0600` and the service user as owner. See
`docs/tenants.example.properties` for the full format. In short:

```properties
tenant.acme.keys=osp_live_9f8a4c2be1d74f06a3c5e2b1d0f7a8c6
tenant.globex.keys=osp_live_44de...,osp_live_1122...
tenant.globex.rate.sustained-capacity=1200
```

The tenant id (`acme`, `globex`) is an opaque string you choose. It appears in logs and in the Prometheus
`tenant` label, so keep secrets out of it. Keys are never written to disk by the proxy and are held in memory only as
SHA-256 hashes. Generate a key from a strong random source, for example:

```bash
head -c 32 /dev/urandom | base64 | tr -d '/+=' | cut -c1-40
```

The proxy re-reads the store whenever its modification time changes, checked at most once per second, so edits take
effect within about a second without a restart.

### How endpoints present the key

The `ProxyBaseUrl` policy points an endpoint's extension at your self-hosted proxy. The tenant key rides along in the
configured header. You have two supported ways to attach it, and you can pick per fleet:

1. Configure the extension to send the header. The extension's proxy provider definition carries request headers, so the
   header and its value can be pushed through the extension's managed configuration for that client. Every endpoint in
   one tenant carries that tenant's key.
2. Inject the header at your reverse proxy. If a given client's endpoints all egress through an Nginx instance you
   control, have that Nginx add `X-Osprey-Tenant-Key` for that client and strip any inbound copy. This keeps the key off
   the endpoints entirely.

Either way, the key identifies the tenant, not the individual endpoint. Endpoint-level and site-level identifiers are
carried separately by the `DeviceTag` and `SiteId` policies.

### Rotating a tenant key

Because a tenant may list several keys at once and the store hot-reloads, rotation is zero-downtime:

1. Generate a new key and add it to the tenant's `keys` line alongside the current one, comma-separated. Save the file.
   Both keys are now valid.
2. Roll the new key out to that tenant's endpoints, by updating the extension configuration or the Nginx injection,
   whichever you use.
3. Once every endpoint presents the new key, remove the old key from the `keys` line and save. The old key stops working
   within about a second.

To revoke a compromised key immediately, delete it from the `keys` line and save. To disable a whole tenant, remove its
lines from the store.

## Per-tenant rate limiting

Two layers work together so no client can starve another.

A per-tenant aggregate budget is checked at authentication time, keyed by tenant alone across all of that tenant's IPs
and providers. Its defaults come from `osprey.tenant.rate.*` and can be overridden per tenant in the store. A tenant
over its burst or sustained allowance receives `429`.

Underneath that, the existing per-provider, per-IP token buckets are namespaced by tenant, so even within one tenant the
buckets of one client's IPs are disjoint from another client's. When tenant authentication is off, this namespacing is
not applied and bucketing is by hashed IP exactly as before.

## Per-tenant metrics

The `tenant` label is added to two Prometheus counters:

- `osprey_requests_total{provider,tenant}`
- `osprey_requests_blocked{provider,status,tenant}`

The label value is the resolved tenant id for extension traffic, `public` for `/check` traffic, and
`anonymous` when tenant authentication is disabled. Because tenant ids are operator-controlled and bounded in number,
the label cardinality stays manageable. Existing dashboards that group only by `provider` keep working; add `tenant` to
a query to break usage down per client. A simple per-client request rate is:

```promql
sum by (tenant) (rate(osprey_requests_total[5m]))
```

## Controlling which version endpoints run

A self-hoster can also control which build of the extension each client runs, stage an update to a small group first,
and roll back a bad build, instead of letting the browser update from the public store on its own schedule. This is
handled by the built-in CRX update server, which is off by default and turned on with `osprey.updates.enabled=true`. The
full setup, the force-install policy snippets, and how channels, pins, and rollbacks work are covered in
`docs/updates.md`.

## Minimal production checklist

- Nginx in front, TLS terminated, `X-Real-IP` set from `$remote_addr`, inbound `X-Real-IP` and
  `X-Forwarded-For` stripped, `/actuator` not proxied.
- `osprey.store.path` directory present and writable, or the store disabled.
- Prometheus scraping `127.0.0.1:9090/actuator/prometheus` over the internal network only.
- For MSP use: `osprey.tenant.auth.enabled=true`, a `0600` tenant store outside the repo, at least one tenant with a
  key, and each fleet configured to present its tenant key.
- For version control: `osprey.updates.enabled=true`, a populated updates directory, `osprey.updates.base-url` set to
  the public origin, and each fleet's force-install update URL pointed at its channel. See `docs/updates.md`.
