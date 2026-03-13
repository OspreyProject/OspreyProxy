# OspreyProxy

Backend code for our [proxy server](https://api.osprey.ac) using Spring MVC
for [Osprey: Browser Protection](https://osprey.ac).

## Features

- **Multi-provider proxy**: Routes URL-checking requests to multiple protection providers through a single API, hiding
  upstream credentials from clients.
- **Per-IP, per-provider rate limiting**: Triple-layer burst + sustained + invalid-request token
  buckets ([Bucket4j](https://github.com/bucket4j/bucket4j) + [Caffeine](https://github.com/ben-manes/caffeine))
  tracking up to 100K IPs per cache with salted SHA-256 hashing. Each provider can have custom rate limit settings
  (capacity, refill interval, etc.), allowing fine-grained control over request limits for different upstreams. Repeated
  violations trigger exponential backoff blocking (doubling block duration per violation, capped at 1 hour).
- **SSRF-hardened**: Custom Apache HttpClient `DnsResolver` blocks private IPs at connection time (not just before the
  request), preventing DNS rebinding attacks. Covers IPv4, IPv6, IPv4-mapped IPv6, Teredo, 6to4, and carrier-grade NAT
  ranges. Also blocks private hostnames (`localhost`, `.local`, `.internal`, etc.) and raw IP literals before the
  request is sent.
- **Input & output validation**: Enforces URL scheme allowlist (http/https only), 8192-character URL length limit, 100
  KB upstream response cap, strict single-field JSON body parsing with non-string value rejection, and JSON
  re-serialization to strip unexpected content. Upstream responses are also validated as well-formed JSON with a manual
  nesting depth check (max 50) as defense-in-depth.
- **Annotation-based routing**: Uses Spring MVC's `@RestController` API for clean, declarative endpoint definitions
  with virtual thread execution, allowing blocking upstream HTTP calls to park rather than occupy platform threads.
- **Security by default**: HSTS, CSP, X-Frame-Options, Content-Type enforcement, Referrer-Policy, Permissions-Policy,
  no redirect following, no error detail leakage, server header suppressed, and API keys loaded from environment
  variables. Bounded upstream connection pool (200 max connections) with 5-second connect, response, and connection
  request timeouts.
- **Built-in stress testing**: Toggle a single property (`ospreyproxy.stress-test-mode=true`) to bypass upstream
  providers and load test the full request pipeline with synthetic IPs. Must never be enabled in production!

## Privacy

OspreyProxy does not log, store, or persist any user data. There is no database, no disk writes, no user-identifiable
analytics, no cookies, and no user accounts.

- **IP addresses** are held in memory only for rate limiting, hashed with SHA-256 and a random salt that changes every
  restart. Raw IPs are never logged or sent upstream.
- **URLs** submitted for checking are forwarded to the upstream providers and then discarded. Refer to each provider's
  privacy policy for how they handle submitted URLs.
- **No request logging**: The application contains zero logging calls that record user-supplied content (such as IPs,
  URLs, hosts, and request bodies). All `log.warn` calls contain no user data and only log internal events, errors, or
  aggregate request counts (total requests and requests per minute, per provider, excluding IPs, URLs, or any
  user-supplied content). The root log level is set to `WARN` and no log file path is configured. These are verifiable
  in [`application.properties`](src/main/resources/application.properties).
- **All in-memory caches** (IP hashes, rate limit buckets, blocked IP sets, violation counts) are bounded,
  non-persistent, and lost on restart.
- **Cloudflare**: Requests are proxied through [Cloudflare](https://www.cloudflare.com/) (orange cloud enabled) for
  DDoS protection and bot mitigation. Cloudflare terminates TLS at their edge, meaning they can see request and response
  traffic before it reaches our origin server. The origin firewall only accepts connections from
  [Cloudflare IP ranges](https://www.cloudflare.com/ips/). Refer to
  [Cloudflare's privacy policy](https://www.cloudflare.com/privacypolicy/) for how they handle traffic data.

##

<p align="center">
  <a href="https://heavynode.com/vps/performance-compute" title="HeavyNode"><img src="https://i.imgur.com/7cF1yaL.png" alt="HeavyNode"></a>
</p>
