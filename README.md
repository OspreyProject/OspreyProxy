# OspreyProxy

Backend code for our [proxy server](https://api.osprey.ac) using Spring MVC
for [Osprey: Browser Protection](https://osprey.ac).

## Features

- **Multi-provider proxy**: Routes URL-checking requests to multiple protection providers through a single API, hiding
  upstream credentials from clients.
- **Per-IP, per-provider rate limiting**: Triple-layer burst + sustained + invalid-request token buckets
  ([Bucket4j](https://github.com/bucket4j/bucket4j) + [Caffeine](https://github.com/ben-manes/caffeine))
  tracking up to 100K IPs per cache with HMAC-SHA256 hashing (random per-restart key). Repeated violations trigger
  exponential backoff blocking to mitigate abuse and DoS attempts.
- **SSRF-hardened**: Custom Apache HttpClient DNS resolver blocks private and reserved IP ranges at connection time,
  preventing DNS rebinding attacks. Also blocks private hostnames and raw IP literals before the request is sent.
- **Input & output validation**: Enforces a URL scheme allowlist, request body and URL length limits, port range
  validation, and strict single-field JSON body parsing. Upstream responses are validated as well-formed JSON with a
  size cap as defense-in-depth.
- **Virtual thread execution**: Blocking upstream HTTP calls park rather than occupy platform threads, keeping
  concurrency high without manual thread pool tuning.
- **Security by default**: HSTS, CSP, Cache-Control restrictions, X-Frame-Options, Content-Type enforcement,
  Referrer-Policy, Permissions-Policy, no redirect following, no error detail leakage, and API keys loaded from
  environment variables.

## Privacy

OspreyProxy keeps no user accounts, cookies, or user-identifiable analytics. It is not stateless, though: some data is
logged or written to disk, as described below.

- **IP addresses** are held in memory only for rate limiting, hashed with HMAC-SHA256 using a random key that changes
  every restart. Raw IPs are never logged. The one exception is the Cloudflare Turnstile check on `/check` and the
  contact form, where the client IP is passed to Cloudflare as `remoteip`. `X-Real-IP` is honored only when the socket
  peer is in `osprey.proxy.trusted-addresses` (loopback by default).
- **Provider lookups** (`POST /{provider}`): URLs are forwarded to the upstream providers and not stored. Refer to each
  provider's privacy policy for how they handle submitted URLs.
- **`/check` scans** are stored in a SQLite database (`osprey.store.path`): the canonical URL, per-provider verdicts,
  and scan timestamps. Non-flagged records are pruned after `osprey.store.retention.days`; phishing and malicious
  records are kept and host-level ones may be published as public result pages on osprey.ac and announced to IndexNow.
  `/result` only returns records that are already published this way. Set `osprey.store.enabled=false` to disable the
  store.
- **Contact form** submissions (name, email, company, message) are stored in the same database.
- **Logging**: the root log level is `WARN` and no log file path is configured, but warnings can contain user-supplied
  content: a URL that a provider flags as phishing or malicious is logged with its full canonical URL, and malformed
  URLs are logged as received. Request bodies and raw IPs are not logged. These are verifiable in
  [`application.properties`](src/main/resources/application.properties).
- **All in-memory caches** (IP hashes, rate limit buckets, blocked IP sets, violation counts) are bounded,
  non-persistent, and lost on restart.

##

<p align="center">
  <a href="https://heavynode.com/vps/performance-compute" title="HeavyNode"><img src="https://i.imgur.com/7cF1yaL.png" alt="HeavyNode"></a>
</p>
