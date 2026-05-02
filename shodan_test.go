package main_test

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/NullAILab/37-self-hosted-shodan-clone/api"
	"github.com/NullAILab/37-self-hosted-shodan-clone/scanner"
	"github.com/NullAILab/37-self-hosted-shodan-clone/store"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func templateDir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "templates")
}

func newTestServer(t *testing.T) (*store.HostStore, *httptest.Server) {
	t.Helper()
	db := store.New()
	srv, err := api.New(db, templateDir())
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return db, ts
}

func startEchoServer(t *testing.T, banner string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				fmt.Fprint(c, banner)
				// drain input
				buf := make([]byte, 256)
				c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				c.Read(buf)
			}(conn)
		}
	}()
	return ln.Addr().String() // "127.0.0.1:PORT"
}

// ---------------------------------------------------------------------------
// ExpandCIDR
// ---------------------------------------------------------------------------

func TestExpandCIDR_Slash30(t *testing.T) {
	hosts, err := scanner.ExpandCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /30 has 4 IPs: network (.0), two hosts (.1, .2), broadcast (.3)
	if len(hosts) != 2 {
		t.Errorf("want 2 hosts, got %d: %v", len(hosts), hosts)
	}
}

func TestExpandCIDR_Slash32(t *testing.T) {
	hosts, err := scanner.ExpandCIDR("10.0.0.1/32")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /32 — single host, no broadcast/network distinction; we skip both so get 0
	// (network == broadcast for /32)
	if len(hosts) != 0 {
		t.Errorf("want 0 usable hosts for /32, got %d", len(hosts))
	}
}

func TestExpandCIDR_Invalid(t *testing.T) {
	_, err := scanner.ExpandCIDR("not-a-cidr")
	if err == nil {
		t.Error("want error for invalid CIDR")
	}
}

func TestExpandCIDR_Slash29(t *testing.T) {
	hosts, err := scanner.ExpandCIDR("10.0.0.0/29")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /29: 8 IPs, 6 usable hosts
	if len(hosts) != 6 {
		t.Errorf("want 6 hosts, got %d", len(hosts))
	}
}

// ---------------------------------------------------------------------------
// Fingerprinting
// ---------------------------------------------------------------------------

func TestIdentifyService_SSH(t *testing.T) {
	svc := scanner.IdentifyService(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
	if svc != "ssh" {
		t.Errorf("want ssh, got %s", svc)
	}
}

func TestIdentifyService_HTTP(t *testing.T) {
	svc := scanner.IdentifyService(80, "HTTP/1.1 200 OK\r\nServer: nginx")
	if svc != "http" {
		t.Errorf("want http, got %s", svc)
	}
}

func TestIdentifyService_FTP(t *testing.T) {
	svc := scanner.IdentifyService(21, "220 ProFTPD 1.3.8 Server (FTP)")
	if svc != "ftp" {
		t.Errorf("want ftp, got %s", svc)
	}
}

func TestIdentifyService_SMTP(t *testing.T) {
	svc := scanner.IdentifyService(25, "220 mail.example.com ESMTP Postfix")
	if svc != "smtp" {
		t.Errorf("want smtp, got %s", svc)
	}
}

func TestIdentifyService_Redis(t *testing.T) {
	svc := scanner.IdentifyService(6379, "+PONG\r\n")
	if svc != "redis" {
		t.Errorf("want redis, got %s", svc)
	}
}

func TestIdentifyService_FallbackToKnownPort(t *testing.T) {
	svc := scanner.IdentifyService(3306, "")
	if svc != "mysql" {
		t.Errorf("want mysql fallback, got %s", svc)
	}
}

func TestIdentifyService_Unknown(t *testing.T) {
	svc := scanner.IdentifyService(9999, "gibberish data")
	if svc != "unknown" {
		t.Errorf("want unknown, got %s", svc)
	}
}

func TestExtractVersion_SSH(t *testing.T) {
	ver := scanner.ExtractVersion("ssh", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
	if !strings.Contains(ver, "OpenSSH") {
		t.Errorf("want OpenSSH in version, got %q", ver)
	}
}

func TestExtractVersion_HTTP_ServerHeader(t *testing.T) {
	banner := "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n"
	ver := scanner.ExtractVersion("http", banner)
	if !strings.Contains(ver, "nginx") {
		t.Errorf("want nginx in version, got %q", ver)
	}
}

func TestExtractVersion_EmptyBanner(t *testing.T) {
	if ver := scanner.ExtractVersion("ssh", ""); ver != "" {
		t.Errorf("want empty version for empty banner, got %q", ver)
	}
}

// ---------------------------------------------------------------------------
// GrabBanner — uses a real local TCP listener
// ---------------------------------------------------------------------------

func TestGrabBanner_ReturnsServerData(t *testing.T) {
	addr := startEchoServer(t, "SSH-2.0-OpenSSH_8.9p1 Test\r\n")
	parts := strings.SplitN(addr, ":", 2)
	ip, portStr := parts[0], parts[1]

	var port int
	fmt.Sscanf(portStr, "%d", &port)

	cfg := scanner.DefaultConfig()
	cfg.DialTimeout = 2 * time.Second
	cfg.BannerTimeout = 1 * time.Second

	banner, err := scanner.GrabBanner(ip, port, cfg)
	if err != nil {
		t.Fatalf("GrabBanner error: %v", err)
	}
	if !strings.Contains(banner, "SSH-2.0") {
		t.Errorf("expected SSH banner, got %q", banner)
	}
}

func TestGrabBanner_ClosedPort(t *testing.T) {
	cfg := scanner.DefaultConfig()
	cfg.DialTimeout = 200 * time.Millisecond
	_, err := scanner.GrabBanner("127.0.0.1", 1, cfg) // port 1 is almost always closed
	if err == nil {
		t.Skip("port 1 happened to be open")
	}
}

// ---------------------------------------------------------------------------
// ScanHost — local mock server
// ---------------------------------------------------------------------------

func TestScanHost_DetectsOpenPort(t *testing.T) {
	addr := startEchoServer(t, "SSH-2.0-OpenSSH_9.0 TestServer\r\n")
	parts := strings.SplitN(addr, ":", 2)
	ip, portStr := parts[0], parts[1]

	var port int
	fmt.Sscanf(portStr, "%d", &port)

	cfg := scanner.ScanConfig{
		Concurrency:   1,
		DialTimeout:   500 * time.Millisecond,
		BannerTimeout: 500 * time.Millisecond,
		BannerSize:    256,
	}
	results := scanner.ScanHost(ip, []int{port, port + 1}, cfg)
	if len(results) != 1 {
		t.Errorf("want 1 open port, got %d", len(results))
	}
	if results[0].Port != port {
		t.Errorf("unexpected port %d", results[0].Port)
	}
}

// ---------------------------------------------------------------------------
// HostStore
// ---------------------------------------------------------------------------

func TestStore_UpsertAndGet(t *testing.T) {
	s := store.New()
	rec := store.ServiceRecord{
		IP: "10.0.0.1", Port: 22, Service: "ssh", Banner: "SSH-2.0-OpenSSH_8.9",
	}
	s.Upsert(rec)
	host, ok := s.Get("10.0.0.1")
	if !ok {
		t.Fatal("expected host to exist")
	}
	if len(host.Services) != 1 || host.Services[0].Port != 22 {
		t.Errorf("unexpected services: %+v", host.Services)
	}
}

func TestStore_UpsertUpdatesExistingPort(t *testing.T) {
	s := store.New()
	s.Upsert(store.ServiceRecord{IP: "10.0.0.1", Port: 80, Banner: "old"})
	s.Upsert(store.ServiceRecord{IP: "10.0.0.1", Port: 80, Banner: "new"})
	host, _ := s.Get("10.0.0.1")
	if len(host.Services) != 1 {
		t.Errorf("want 1 service after update, got %d", len(host.Services))
	}
	if host.Services[0].Banner != "new" {
		t.Errorf("want updated banner 'new', got %q", host.Services[0].Banner)
	}
}

func TestStore_GetMissing(t *testing.T) {
	s := store.New()
	_, ok := s.Get("1.2.3.4")
	if ok {
		t.Error("expected false for missing host")
	}
}

func TestStore_Count(t *testing.T) {
	s := store.New()
	s.Upsert(store.ServiceRecord{IP: "10.0.0.1", Port: 22})
	s.Upsert(store.ServiceRecord{IP: "10.0.0.2", Port: 80})
	if s.Count() != 2 {
		t.Errorf("want 2 hosts, got %d", s.Count())
	}
}

func TestStore_ServiceCount(t *testing.T) {
	s := store.New()
	s.Upsert(store.ServiceRecord{IP: "10.0.0.1", Port: 22})
	s.Upsert(store.ServiceRecord{IP: "10.0.0.1", Port: 80})
	s.Upsert(store.ServiceRecord{IP: "10.0.0.2", Port: 22})
	if s.ServiceCount() != 3 {
		t.Errorf("want 3 services, got %d", s.ServiceCount())
	}
}

func TestStore_Search_ByPort(t *testing.T) {
	s := store.New()
	s.Upsert(store.ServiceRecord{IP: "10.0.0.1", Port: 22, Service: "ssh"})
	s.Upsert(store.ServiceRecord{IP: "10.0.0.2", Port: 80, Service: "http"})
	results := s.Search(store.SearchQuery{Port: 22})
	if len(results) != 1 || results[0].Port != 22 {
		t.Errorf("port filter failed: %+v", results)
	}
}

func TestStore_Search_ByService(t *testing.T) {
	s := store.New()
	s.Upsert(store.ServiceRecord{IP: "10.0.0.1", Port: 22, Service: "ssh"})
	s.Upsert(store.ServiceRecord{IP: "10.0.0.2", Port: 80, Service: "http"})
	results := s.Search(store.SearchQuery{Service: "ssh"})
	if len(results) != 1 || results[0].Service != "ssh" {
		t.Errorf("service filter failed: %+v", results)
	}
}

func TestStore_Search_ByBanner(t *testing.T) {
	s := store.New()
	s.Upsert(store.ServiceRecord{IP: "10.0.0.1", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9"})
	s.Upsert(store.ServiceRecord{IP: "10.0.0.2", Port: 80, Banner: "nginx/1.24"})
	results := s.Search(store.SearchQuery{Banner: "openSSH"}) // case-insensitive
	if len(results) != 1 {
		t.Errorf("banner filter failed: %+v", results)
	}
}

func TestStore_Search_ByIPPrefix(t *testing.T) {
	s := store.New()
	s.Upsert(store.ServiceRecord{IP: "10.0.0.1", Port: 22})
	s.Upsert(store.ServiceRecord{IP: "10.0.1.1", Port: 22})
	s.Upsert(store.ServiceRecord{IP: "192.168.1.1", Port: 80})
	results := s.Search(store.SearchQuery{IP: "10.0.0"})
	if len(results) != 1 || results[0].IP != "10.0.0.1" {
		t.Errorf("IP prefix filter failed: %+v", results)
	}
}

func TestStore_Search_EmptyQuery_ReturnsAll(t *testing.T) {
	s := store.New()
	s.Upsert(store.ServiceRecord{IP: "10.0.0.1", Port: 22})
	s.Upsert(store.ServiceRecord{IP: "10.0.0.2", Port: 80})
	results := s.Search(store.SearchQuery{})
	if len(results) != 2 {
		t.Errorf("empty query should return all, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// ParseQuery
// ---------------------------------------------------------------------------

func TestParseQuery_Port(t *testing.T) {
	q := store.ParseQuery("port:22")
	if q.Port != 22 {
		t.Errorf("want Port=22, got %d", q.Port)
	}
}

func TestParseQuery_Service(t *testing.T) {
	q := store.ParseQuery("service:http")
	if q.Service != "http" {
		t.Errorf("want Service=http, got %q", q.Service)
	}
}

func TestParseQuery_Multiple(t *testing.T) {
	q := store.ParseQuery("port:80 service:http ip:192.168")
	if q.Port != 80 || q.Service != "http" || q.IP != "192.168" {
		t.Errorf("multi-token parse failed: %+v", q)
	}
}

func TestParseQuery_BareWord(t *testing.T) {
	q := store.ParseQuery("nginx")
	if q.Banner != "nginx" {
		t.Errorf("bare word should set Banner, got %q", q.Banner)
	}
}

// ---------------------------------------------------------------------------
// HTTP API
// ---------------------------------------------------------------------------

func TestAPI_Health(t *testing.T) {
	_, ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("want 200, got %d", resp.StatusCode)
	}
}

func TestAPI_Stats_Empty(t *testing.T) {
	_, ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/api/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var stats map[string]int
	json.NewDecoder(resp.Body).Decode(&stats)
	if stats["hosts"] != 0 {
		t.Errorf("want 0 hosts in empty store, got %d", stats["hosts"])
	}
}

func TestAPI_Search_Empty(t *testing.T) {
	_, ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/api/search?q=port:22")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("want 200, got %d", resp.StatusCode)
	}
}

func TestAPI_Host_NotFound(t *testing.T) {
	_, ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/api/host/1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("want 404 for missing host, got %d", resp.StatusCode)
	}
}

func TestAPI_Search_ReturnsIndexedData(t *testing.T) {
	db, ts := newTestServer(t)
	db.Upsert(store.ServiceRecord{
		IP: "10.0.0.5", Port: 22, Service: "ssh",
		Banner: "SSH-2.0-OpenSSH_9.0", ScannedAt: time.Now(),
	})

	resp, err := http.Get(ts.URL + "/api/search?q=port:22")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	count := int(result["count"].(float64))
	if count != 1 {
		t.Errorf("want 1 result, got %d", count)
	}
}

func TestAPI_Host_ReturnsData(t *testing.T) {
	db, ts := newTestServer(t)
	db.Upsert(store.ServiceRecord{
		IP: "10.1.2.3", Port: 80, Service: "http", ScannedAt: time.Now(),
	})

	resp, err := http.Get(ts.URL + "/api/host/10.1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("want 200, got %d", resp.StatusCode)
	}
	var host store.HostRecord
	json.NewDecoder(resp.Body).Decode(&host)
	if host.IP != "10.1.2.3" {
		t.Errorf("want IP 10.1.2.3, got %q", host.IP)
	}
}

func TestAPI_Scan_InvalidBody(t *testing.T) {
	_, ts := newTestServer(t)
	resp, err := http.Post(ts.URL+"/api/scan", "application/json",
		strings.NewReader(`{"cidr":"not-valid"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		t.Error("want non-200 for invalid CIDR")
	}
}

func TestAPI_IndexPage(t *testing.T) {
	_, ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("want 200 for index, got %d", resp.StatusCode)
	}
}
