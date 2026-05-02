// Package store provides an in-memory index of discovered network services.
package store

import (
	"strings"
	"sync"
	"time"
)

// ServiceRecord describes a single open port on a host.
type ServiceRecord struct {
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	Protocol  string    `json:"protocol"` // always "tcp" for now
	Service   string    `json:"service"`
	Banner    string    `json:"banner"`
	Version   string    `json:"version"`
	ScannedAt time.Time `json:"scanned_at"`
}

// HostRecord aggregates all services discovered on a single IP.
type HostRecord struct {
	IP       string          `json:"ip"`
	Services []ServiceRecord `json:"services"`
	LastSeen time.Time       `json:"last_seen"`
}

// SearchQuery holds parsed search parameters.
type SearchQuery struct {
	IP      string // prefix match on IP
	Port    int    // 0 = any
	Service string // substring match on service name
	Banner  string // substring match on banner
}

// HostStore is a thread-safe in-memory store for host + service records.
type HostStore struct {
	mu    sync.RWMutex
	hosts map[string]*HostRecord // keyed by IP
}

// New returns an empty HostStore.
func New() *HostStore {
	return &HostStore{hosts: make(map[string]*HostRecord)}
}

// Upsert adds or updates a service record.  If the host already has a record
// for this port, it is replaced; otherwise a new service is appended.
func (s *HostStore) Upsert(rec ServiceRecord) {
	if rec.ScannedAt.IsZero() {
		rec.ScannedAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	host, ok := s.hosts[rec.IP]
	if !ok {
		host = &HostRecord{IP: rec.IP}
		s.hosts[rec.IP] = host
	}
	host.LastSeen = rec.ScannedAt

	for i, svc := range host.Services {
		if svc.Port == rec.Port {
			host.Services[i] = rec
			return
		}
	}
	host.Services = append(host.Services, rec)
}

// Get returns the HostRecord for ip, or (zero, false) if not found.
func (s *HostStore) Get(ip string) (HostRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.hosts[ip]
	if !ok {
		return HostRecord{}, false
	}
	return *h, true
}

// All returns a copy of all host records.
func (s *HostStore) All() []HostRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]HostRecord, 0, len(s.hosts))
	for _, h := range s.hosts {
		out = append(out, *h)
	}
	return out
}

// Count returns the number of unique hosts.
func (s *HostStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.hosts)
}

// ServiceCount returns the total number of service records across all hosts.
func (s *HostStore) ServiceCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, h := range s.hosts {
		n += len(h.Services)
	}
	return n
}

// Search returns service records matching the query.
// All non-empty fields are ANDed together.
func (s *HostStore) Search(q SearchQuery) []ServiceRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []ServiceRecord
	for _, host := range s.hosts {
		if q.IP != "" && !strings.HasPrefix(host.IP, q.IP) {
			continue
		}
		for _, svc := range host.Services {
			if q.Port != 0 && svc.Port != q.Port {
				continue
			}
			if q.Service != "" && !strings.Contains(
				strings.ToLower(svc.Service), strings.ToLower(q.Service)) {
				continue
			}
			if q.Banner != "" && !strings.Contains(
				strings.ToLower(svc.Banner), strings.ToLower(q.Banner)) {
				continue
			}
			results = append(results, svc)
		}
	}
	return results
}

// Stats returns aggregate statistics about the indexed data.
func (s *HostStore) Stats() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	byService := make(map[string]int)
	byPort := make(map[int]int)

	for _, host := range s.hosts {
		for _, svc := range host.Services {
			byService[svc.Service]++
			byPort[svc.Port]++
		}
	}

	stats := map[string]int{
		"hosts":    len(s.hosts),
		"services": 0,
	}
	for _, n := range byService {
		stats["services"] += n
	}
	for svc, n := range byService {
		stats["service:"+svc] = n
	}
	return stats
}

// ParseQuery turns a simple query string into a SearchQuery.
// Supported tokens: port:N  service:NAME  ip:PREFIX  banner:TEXT
func ParseQuery(q string) SearchQuery {
	sq := SearchQuery{}
	for _, token := range strings.Fields(q) {
		kv := strings.SplitN(token, ":", 2)
		if len(kv) != 2 {
			sq.Banner = token // bare word → banner search
			continue
		}
		switch strings.ToLower(kv[0]) {
		case "port":
			var p int
			if _, err := parseIntFast(kv[1], &p); err == nil {
				sq.Port = p
			}
		case "service", "svc":
			sq.Service = kv[1]
		case "ip":
			sq.IP = kv[1]
		case "banner":
			sq.Banner = kv[1]
		}
	}
	return sq
}

func parseIntFast(s string, out *int) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, &parseError{s}
		}
		n = n*10 + int(c-'0')
	}
	*out = n
	return n, nil
}

type parseError struct{ s string }

func (e *parseError) Error() string { return "not an int: " + e.s }
