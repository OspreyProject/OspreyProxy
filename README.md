## OspreyProxy

Backend code for our [proxy server](https://api.osprey.ac) using Spring WebFlux
for [Osprey: Browser Protection](https://osprey.ac).

### VPS Specs

- CPU: 2 vCPU (AMD Ryzen 5950X)
- RAM: 4 GB DDR4 (2 GB swap)
- SSD: 80 GB NVMe

### Performance

These were conducted using OspreyProxy's built-in stress testing tools and a PowerShell script using `hey` for requests.
The server is hosted in Frankfurt, DE and the tests were conducted from a machine in San Diego, CA.

- Average latency: **183.2ms**
- Peak requests per second: **2,708**
- Peak concurrent connections: **6,500**
- Peak req/min (estimated): **68,354**

The server is CPU-bound, but the performance is sufficient for now.
