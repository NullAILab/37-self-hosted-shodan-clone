# Self-Hosted Shodan Clone

![Go](https://img.shields.io/badge/Go-1.21%2B-blue?logo=go)
![Tests](https://img.shields.io/badge/tests-37%20passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT%20%2B%20Responsible%20Use-blue)

Shodan indexes 1.5 billion devices by scanning the entire internet, grabbing the first few hundred bytes each service sends, and making the result searchable. Security teams use it to audit their own attack surface — but that means sending your internal IP ranges to a third-party service. This tool replicates the core workflow locally: it mass-scans CIDR ranges you own with concurrent TCP dials, grabs service banners, identifies protocols from banner content, extracts version strings, and stores everything in a thread-safe in-memory index queryable by port, service name, IP prefix, or banner keyword. No external dependencies, no data leaves your network.

## Features

- **CIDR expansion** — `/24` to individual IPs, skips network and broadcast addresses
- **Concurrent scanner** — goroutine semaphore pattern; configurable concurrency (default 200), dial timeout, and banner size
- **Banner grabbing** — reads raw TCP banner; sends an HTTP probe on ports 80/443/8080/8443 to get HTTP Server headers
- **Service fingerprinting** — 15+ port → service mappings; banner-prefix matching for SSH, FTP, SMTP, Redis, MySQL, and more
- **Version extraction** — pulls version strings from SSH handshake, HTTP `Server:` header, FTP/SMTP banners
- **Thread-safe HostStore** — `sync.RWMutex`-protected in-memory index; upsert by (IP, port)
- **Token query language** — `port:22`, `service:http`, `ip:10.0.0`, `banner:nginx`; tokens ANDed
- **HTTP API** — `/api/scan`, `/api/search`, `/api/host/{ip}`, `/api/stats`
- **Dark dashboard** — Go `html/template` UI with search bar and results table
- **37 tests** — including real local TCP listeners for banner-grab tests

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.21+ |
| Scanner | stdlib `net` + goroutines |
| Store | In-memory `map` + `sync.RWMutex` |
| HTTP server | stdlib `net/http` |
| UI templates | stdlib `html/template` |
| Testing | stdlib `testing` + `httptest` |

Zero external dependencies.

## Project Structure

```
37-self-hosted-shodan-clone/
├── go.mod
├── main.go
├── scanner/
│   ├── scanner.go       ← ExpandCIDR, GrabBanner, ScanHost, ScanCIDR
│   └── fingerprint.go   ← IdentifyService, ExtractVersion, KnownPorts
├── store/
│   └── store.go         ← HostStore, ServiceRecord, ParseQuery, Search
├── api/
│   └── api.go           ← HTTP handlers, Server
├── templates/
│   └── index.html       ← Dark-theme dashboard
├── shodan_test.go        ← 37 tests
├── LICENSE
└── README.md
```

## Usage

```bash
go build -o shodan-clone .

# Start the server
./shodan-clone -addr :8080

# Scan a subnet (only scan networks you own)
curl -X POST http://localhost:8080/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"cidr":"192.168.1.0/24","ports":[22,80,443,8080,3306]}'

# Search indexed services
curl "http://localhost:8080/api/search?q=port:22"
curl "http://localhost:8080/api/search?q=service:http+banner:nginx"
curl "http://localhost:8080/api/search?q=ip:192.168.1"

# Get all services on a specific host
curl "http://localhost:8080/api/host/192.168.1.100"

# Aggregate stats
curl "http://localhost:8080/api/stats"

# Open the dashboard
open http://localhost:8080
```

**Query language:**

| Token | Example | Matches |
|-------|---------|---------|
| `port:N` | `port:22` | Services on port 22 |
| `service:NAME` | `service:http` | Service name contains "http" |
| `ip:PREFIX` | `ip:192.168.1` | IPs starting with prefix |
| `banner:TEXT` | `banner:OpenSSH` | Banner contains text (case-insensitive) |
| bare word | `nginx` | Banner contains bare word |

## Running Tests

```bash
go test ./... -v
```

37 tests covering CIDR expansion, service fingerprinting, banner grabbing (with real local TCP listeners), store search, query parsing, and all HTTP endpoints.

## References

- [Shodan.io — How It Works](https://help.shodan.io/the-basics/what-is-shodan)
- [MITRE ATT&CK T1595 — Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [RFC 793 — Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc793)

## License

MIT License + Responsible Use Guidelines. See [LICENSE](LICENSE) for full terms.
