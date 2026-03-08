# OspreyProxy

Backend code for our [proxy server](https://api.osprey.ac) using Spring WebFlux
for [Osprey: Browser Protection](https://osprey.ac).

## Features

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

## Privacy

OspreyProxy does not log, store, or persist any user data. There is no database, no disk writes, no analytics, no
cookies, and no user accounts.

- **IP addresses** are held in memory only for rate limiting, hashed with SHA-256 and a random salt that changes every
  restart. Raw IPs are never logged or sent upstream.
- **URLs** submitted for checking are forwarded to the upstream providers and then discarded. Refer to each provider's
  privacy policy for how they handle submitted URLs.
- **No request logging**: The application contains zero logging calls that record user-supplied content (such as IPs,
  URLs, hosts, and request bodies). All `log.warn` calls contain no user data and only log internal events or errors.
  The root log level is set to `WARN`, the Reactor Netty access log is explicitly disabled via both property and system
  property, and no log file path is configured. These are verifiable in
  [`application.properties`](src/main/resources/application.properties) and
  [`ReactorConfig.java`](src/main/java/net/foulest/ospreyproxy/config/ReactorConfig.java).
- **All in-memory caches** (IP hashes, rate limit buckets) are bounded, non-persistent, and lost on restart.
- **Cloudflare**: Requests are proxied through [Cloudflare](https://www.cloudflare.com/) (orange cloud enabled) for
  DDoS protection and bot mitigation. Cloudflare terminates TLS at their edge, meaning they can see request and response
  traffic before it reaches our origin server. The origin firewall only accepts connections from
  [Cloudflare IP ranges](https://www.cloudflare.com/ips/). Refer to
  [Cloudflare's privacy policy](https://www.cloudflare.com/privacypolicy/) for how they handle traffic data.
- **Live verification**: https://api.osprey.ac/privacy returns a real-time snapshot of privacy-related configuration
  read directly from the running JVM and OS config files. Checks include:
    - Application log level, file appenders, Reactor Netty access log, and Spring log file paths
    - Nginx access log status (reads the actual Nginx config from disk)
    - Systemd journal persistence (reads `/etc/systemd/journald.conf` from disk)
    - Whether any JDBC database driver is on the classpath
    - Git commit hash and JAR SHA-256 for reproducible build verification:
  ```
  1. Check the commit:   curl -s https://api.osprey.ac/privacy | jq .buildCommit
  2. Clone and build:    git checkout <commit> && ./gradlew bootJar
  3. Compare checksum:   sha256sum build/libs/OspreyProxy.jar
  4. Match against:      curl -s https://api.osprey.ac/privacy | jq .buildJarSha256
  ```

## VPS Specs

- CPU: 2 vCPU (AMD Ryzen 5950X)
- RAM: 4 GB DDR4 (2 GB swap)
- SSD: 80 GB NVMe

## Performance

These synthetic tests were conducted using OspreyProxy's built-in stress testing tools and a PowerShell script using
`hey` for requests. The server is hosted in Frankfurt, DE and the tests were conducted from a machine in San Diego, CA.
These numbers are the most the server can handle before it starts to struggle and the response times reach 2,000 ms or
more.

- Peak concurrent connections: ~**6,500**
- Peak requests per second: ~**3,000**
- Peak req/min (estimated): ~**70,000**
- Peak req/day (estimated): ~**100 million**

The following are (generous) real-time estimates based on the active weekly users of Osprey:

- Estimated average concurrent connections: ~**10**
- Estimated average requests per second: ~**10**
- Estimated average requests per minute: ~**625**
- Estimated average requests per day: ~**900,000**
