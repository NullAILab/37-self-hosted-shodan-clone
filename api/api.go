// Package api provides the HTTP server for the Shodan clone.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/NullAILab/37-self-hosted-shodan-clone/scanner"
	"github.com/NullAILab/37-self-hosted-shodan-clone/store"
)

// Server wraps the HTTP mux and the shared data store.
type Server struct {
	mux   *http.ServeMux
	db    *store.HostStore
	tmpl  *template.Template
}

// New creates a Server, loads templates from the given directory, and registers routes.
func New(db *store.HostStore, templateDir string) (*Server, error) {
	pattern := filepath.Join(templateDir, "*.html")
	tmpl, err := template.ParseGlob(pattern)
	if err != nil {
		return nil, fmt.Errorf("load templates: %w", err)
	}

	s := &Server{mux: http.NewServeMux(), db: db, tmpl: tmpl}
	s.routes()
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("/", s.handleIndex)
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/scan", s.handleScan)
	s.mux.HandleFunc("/api/search", s.handleSearch)
	s.mux.HandleFunc("/api/host/", s.handleHost)
	s.mux.HandleFunc("/api/stats", s.handleStats)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	all := s.db.All()
	stats := s.db.Stats()
	data := map[string]any{
		"hosts": all,
		"stats": stats,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type ScanRequest struct {
	CIDR    string `json:"cidr"`
	Ports   []int  `json:"ports"`
	Timeout int    `json:"timeout_s"` // dial timeout in seconds
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.CIDR == "" {
		http.Error(w, "cidr is required", http.StatusBadRequest)
		return
	}
	if len(req.Ports) == 0 {
		req.Ports = []int{22, 80, 443, 8080, 3306, 5432, 6379, 27017}
	}

	cfg := scanner.DefaultConfig()
	if req.Timeout > 0 {
		cfg.DialTimeout = time.Duration(req.Timeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	ch, err := scanner.ScanCIDR(ctx, req.CIDR, req.Ports, cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var found int
	for res := range ch {
		if res.Open {
			s.db.Upsert(store.ServiceRecord{
				IP:       res.IP,
				Port:     res.Port,
				Protocol: "tcp",
				Service:  res.Service,
				Banner:   res.Banner,
				Version:  res.Version,
			})
			found++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"cidr":          req.CIDR,
		"ports_scanned": req.Ports,
		"open_ports":    found,
		"hosts_indexed": s.db.Count(),
	})
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if q == "" {
		// Allow individual parameters too
		q = buildQueryFromParams(r)
	}
	sq := store.ParseQuery(q)
	results := s.db.Search(sq)
	writeJSON(w, http.StatusOK, map[string]any{
		"query":   q,
		"count":   len(results),
		"results": results,
	})
}

func (s *Server) handleHost(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimPrefix(r.URL.Path, "/api/host/")
	if ip == "" {
		http.Error(w, "ip required", http.StatusBadRequest)
		return
	}
	host, ok := s.db.Get(ip)
	if !ok {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, host)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.db.Stats())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func buildQueryFromParams(r *http.Request) string {
	parts := []string{}
	if p := r.URL.Query().Get("port"); p != "" {
		if _, err := strconv.Atoi(p); err == nil {
			parts = append(parts, "port:"+p)
		}
	}
	if s := r.URL.Query().Get("service"); s != "" {
		parts = append(parts, "service:"+s)
	}
	if ip := r.URL.Query().Get("ip"); ip != "" {
		parts = append(parts, "ip:"+ip)
	}
	if b := r.URL.Query().Get("banner"); b != "" {
		parts = append(parts, "banner:"+b)
	}
	_ = runtime.Version() // prevent unused import
	return strings.Join(parts, " ")
}
