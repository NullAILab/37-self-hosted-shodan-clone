package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// ScanConfig controls scanner behaviour.
type ScanConfig struct {
	// Concurrency is the maximum number of simultaneous TCP dials.
	Concurrency int
	// DialTimeout is the per-connection connect timeout.
	DialTimeout time.Duration
	// BannerTimeout is the deadline for reading a banner after connecting.
	BannerTimeout time.Duration
	// BannerSize is the maximum bytes read per banner (default 1024).
	BannerSize int
}

// DefaultConfig returns a ScanConfig suitable for scanning a local /24 quickly.
func DefaultConfig() ScanConfig {
	return ScanConfig{
		Concurrency:   200,
		DialTimeout:   2 * time.Second,
		BannerTimeout: 3 * time.Second,
		BannerSize:    1024,
	}
}

// ScanResult holds the outcome of scanning a single IP:port combination.
type ScanResult struct {
	IP      string
	Port    int
	Open    bool
	Banner  string
	Service string
	Version string
	Error   string
}

// ExpandCIDR returns all usable host IPs in the given CIDR block.
// E.g. "192.168.1.0/30" → ["192.168.1.1", "192.168.1.2"]
func ExpandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	// Convert to uint32 for iteration.
	start := ipToUint32(ip.Mask(ipnet.Mask))
	end := start | ^ipToUint32(net.IP(ipnet.Mask))

	var hosts []string
	for i := start + 1; i < end; i++ { // skip network and broadcast
		hosts = append(hosts, uint32ToIP(i).String())
	}
	return hosts, nil
}

// GrabBanner connects to ip:port, optionally sends an HTTP probe, and returns
// the first BannerSize bytes of the server's response.
func GrabBanner(ip string, port int, cfg ScanConfig) (string, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, cfg.DialTimeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// For HTTP ports, send a minimal GET request to elicit a response.
	if port == 80 || port == 8080 || port == 8000 || port == 8443 || port == 443 {
		fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", ip)
	}

	conn.SetReadDeadline(time.Now().Add(cfg.BannerTimeout))
	size := cfg.BannerSize
	if size <= 0 {
		size = 1024
	}
	buf := make([]byte, size)
	n, _ := conn.Read(buf)
	return string(buf[:n]), nil
}

// ScanHost scans all given ports on a single IP and returns results for open ports.
func ScanHost(ip string, ports []int, cfg ScanConfig) []ScanResult {
	var results []ScanResult
	for _, port := range ports {
		banner, err := GrabBanner(ip, port, cfg)
		if err != nil {
			// Port closed or filtered.
			continue
		}
		svc := IdentifyService(port, banner)
		ver := ExtractVersion(svc, banner)
		results = append(results, ScanResult{
			IP:      ip,
			Port:    port,
			Open:    true,
			Banner:  banner,
			Service: svc,
			Version: ver,
		})
	}
	return results
}

// ScanCIDR scans all hosts in the CIDR range for the given ports.
// Results are sent on the returned channel; the channel is closed when done.
// Cancel ctx to abort early.
func ScanCIDR(
	ctx context.Context,
	cidr string,
	ports []int,
	cfg ScanConfig,
) (<-chan ScanResult, error) {
	hosts, err := ExpandCIDR(cidr)
	if err != nil {
		return nil, err
	}

	out := make(chan ScanResult, 1024)
	sem := make(chan struct{}, cfg.Concurrency)

	go func() {
		defer close(out)
		var wg sync.WaitGroup

		for _, ip := range hosts {
			select {
			case <-ctx.Done():
				return
			default:
			}

			wg.Add(1)
			go func(host string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				results := ScanHost(host, ports, cfg)
				for _, r := range results {
					select {
					case out <- r:
					case <-ctx.Done():
						return
					}
				}
			}(ip)
		}
		wg.Wait()
	}()

	return out, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}
