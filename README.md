# OspreyProxy

Backend code for our [proxy server](https://api.osprey.ac) using Spring MVC
for [Osprey: Browser Protection](https://osprey.ac).

## Features

- **Multi-provider proxy**: Routes URL-checking requests to multiple protection providers through a single API, hiding
  upstream credentials from clients.
- **Per-IP, per-provider rate limiting**: Triple-layer burst + sustained + invalid-request token
  buckets ([Bucket4j](https://github.com/bucket4j/bucket4j) + [Caffeine](https://github.com/ben-manes/caffeine))
  tracking up to 100K IPs per cache with HMAC-SHA256 hashing (random per-restart key). Repeated violations trigger
  exponential backoff blocking to mitigate abuse and DoS attempts.
- **SSRF-hardened**: Custom Apache HttpClient DNS resolver blocks private and reserved IP ranges at connection time,
  preventing DNS rebinding attacks. Also blocks private hostnames and raw IP literals before the request is sent.
- **Input & output validation**: Enforces a URL scheme allowlist, request body and URL length limits, port range
  validation, strict single-field JSON body parsing, and DNS existence validation via Cloudflare's DoH API before
  forwarding to any upstream. Upstream responses are validated as well-formed JSON with a size cap as defense-in-depth.
- **Virtual thread execution**: Blocking upstream HTTP calls park rather than occupy platform threads, keeping
  concurrency high without manual thread pool tuning.
- **Security by default**: HSTS, CSP, Cache-Control restrictions, X-Frame-Options, Content-Type enforcement,
  Referrer-Policy, Permissions-Policy, no redirect following, no error detail leakage, and API keys loaded from
  environment variables.

## Privacy

OspreyProxy does not log, store, or persist any user data. There is no database, no disk writes, no user-identifiable
analytics, no cookies, and no user accounts.

- **IP addresses** are held in memory only for rate limiting, hashed with HMAC-SHA256 using a random key that changes
  every restart. Raw IPs are never logged or sent upstream.
- **URLs** submitted for checking are forwarded to the upstream providers and then discarded. Refer to each provider's
  privacy policy for how they handle submitted URLs.
- **Minimal request logging**: User-supplied content may appear in logs only on upstream errors or unexpected internal
  failures. IPs and request bodies are never logged. The root log level is set to `WARN` and no log file path is
  configured. These are verifiable in [`application.properties`](src/main/resources/application.properties).
- **All in-memory caches** (IP hashes, rate limit buckets, blocked IP sets, violation counts) are bounded,
  non-persistent, and lost on restart.
- **Cloudflare**: Requests are proxied through [Cloudflare](https://www.cloudflare.com) (orange cloud enabled) for DDoS
  protection and bot mitigation. Cloudflare terminates TLS at their edge, meaning they can see request and response
  traffic before it reaches our origin server. The origin firewall only accepts connections
  from [Cloudflare IP ranges](https://www.cloudflare.com/ips). Refer
  to [Cloudflare's privacy policy](https://www.cloudflare.com/privacypolicy) for how they handle traffic data.

##

<p align="center">
  <a href="https://heavynode.com/vps/performance-compute" title="HeavyNode"><img src="https://i.imgur.com/7cF1yaL.png" alt="HeavyNode"></a>
</p>
