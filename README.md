## OspreyProxy

Backend code for our [proxy server](https://api.osprey.ac) using Spring WebFlux
for [Osprey: Browser Protection](https://osprey.ac).

### Features

- **Multi-provider proxy**: Routes URL-checking requests to [AlphaMountain](https://alphamountain.ai)
  and [PrecisionSec](https://precisionsec.com) through a single API, hiding upstream credentials from clients
- **Per-IP rate limiting**: Dual-layer burst + sustained token
  buckets ([Bucket4j](https://github.com/bucket4j/bucket4j) + [Caffeine](https://github.com/ben-manes/caffeine))
  tracking up to 100K IPs with salted SHA-256 hashing
- **SSRF-hardened**: Custom DNS resolver blocks private IPs at connection time (not just before the request), preventing
  DNS rebinding attacks. Covers IPv4, IPv6, IPv4-mapped IPv6, Teredo, 6to4, and carrier-grade NAT ranges
- **Input & output validation**: Enforces URL scheme/length/format, 10 KB request body streaming limit, 100 KB upstream
  response cap, and JSON re-serialization to strip unexpected content
- **Security by default**: HSTS, CSP, X-Frame-Options, Content-Type enforcement, no redirect following, no error detail
  leakage, and API keys loaded from environment variables over HTTPS only
- **Built-in stress testing**: Toggle a single property to bypass upstream providers and load test the full request
  pipeline with synthetic IPs

### Privacy

OspreyProxy does not log, store, or persist any user data. There is no database, no disk writes, no analytics, no
cookies, and no user accounts.

- **IP addresses** are held in memory only for rate limiting, hashed with SHA-256 and a random salt that changes every
  restart. Raw IPs are never logged or sent upstream.
- **URLs** submitted for checking are forwarded to the upstream
  provider ([AlphaMountain](https://alphamountain.ai/privacy-policy) or [PrecisionSec](https://precisionsec.com)) and
  then discarded. Refer to each provider's privacy policy for how they handle submitted URLs.
- **No request logging**: application logging is set to WARN level, so individual requests are never written to disk.
- **All in-memory caches** (IP hashes, rate limit buckets) are bounded, non-persistent, and lost on restart.

### VPS Specs

- CPU: 2 vCPU (AMD Ryzen 5950X)
- RAM: 4 GB DDR4 (2 GB swap)
- SSD: 80 GB NVMe

### Performance

These were conducted using OspreyProxy's built-in stress testing tools and a PowerShell script using `hey` for requests.
The server is hosted in Frankfurt, DE and the tests were conducted from a machine in San Diego, CA. These numbers are
the most the server can handle before it starts to struggle and the response times reach 2,000 ms or more.

- Peak concurrent connections: ~**6,500**
- Peak requests per second: ~**3,000**
- Peak req/min (estimated): ~**70,000**
- Peak req/day (estimated): ~**100 million**

The following are (generous) estimates based on the active weekly users of Osprey:

- Estimated average concurrent connections: ~**10**
- Estimated average requests per second: ~**10**
- Estimated average requests per minute: ~**625**
- Estimated average requests per day: ~**900,000**
