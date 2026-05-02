# 37 — Self-Hosted Shodan Clone

> **Difficulty:** Intermediate | **Time:** 3–5 days | **Language:** Go

Self-hosted network intelligence platform — scans your own networks, fingerprints
services via banner grabbing, indexes everything in memory, and exposes a
Shodan-style query interface.

---

## What It Does

- **Scanner** — concurrent TCP port scanner with configurable concurrency, timeout, and port list
- **Fingerprinter** — banner grabbing + service identification (SSH, HTTP, FTP, SMTP, Redis, MySQL, …)
- **Version extraction** — pulls version strings from SSH, HTTP Server headers, FTP/SMTP banners
- **HostStore** — thread-safe in-memory index with upsert, get-by-IP, search, stats
- **Search** — token query language: `port:22`, `service:http`, `ip:10.0.0`, `banner:nginx`
- **HTTP API** — scan, search, get-by-host, stats endpoints
- **Dashboard** — Go HTML template with search bar, service table, stats

---

## Tech Stack

| Component    | Technology                   |
|--------------|------------------------------|
| Language     | Go 1.21+                     |
| Scanner      | stdlib `net` + goroutines    |
| Store        | In-memory map + `sync.RWMutex` |
| HTTP server  | stdlib `net/http`            |
| UI templates | stdlib `html/template`       |
| Tests        | stdlib `testing`             |

Zero external dependencies.

---

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
│   └── index.html       ← dark-theme dashboard
├── shodan_test.go        ← 37 tests
├── LICENSE
└── README.md
```

---

## Usage

```bash
# Build
go build -o shodan-clone .

# Start the server
./shodan-clone -addr :8080

# Scan a subnet (scan only networks you own)
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

# Dashboard
open http://localhost:8080
```

**Query language:**

| Token          | Example            | Matches                          |
|----------------|--------------------|----------------------------------|
| `port:N`       | `port:22`          | Services on port 22              |
| `service:NAME` | `service:http`     | Service name contains "http"     |
| `ip:PREFIX`    | `ip:192.168.1`     | IPs starting with prefix         |
| `banner:TEXT`  | `banner:OpenSSH`   | Banner contains text (case-insensitive) |
| bare word      | `nginx`            | Banner contains bare word        |

---

## Running Tests

```bash
go test ./... -v
```

37 tests covering CIDR expansion, service fingerprinting, banner grabbing (using
real local TCP listeners), store search, query parsing, and all HTTP endpoints.

---

## Learning Objectives

- How Shodan works: mass TCP scanning + banner grabbing
- Go goroutines and semaphore pattern for concurrent scanning
- Service fingerprinting from protocol banners
- Thread-safe data structures with `sync.RWMutex`
- Network inventory: understanding your own attack surface

---

*NullAI Lab — Project 37 | Self-Hosted Shodan Clone*
