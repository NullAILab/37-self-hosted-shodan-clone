// Binary: shodan-clone
//
// Self-hosted network intelligence platform — scans your own network,
// fingerprints services, and exposes a Shodan-like query interface.
//
// [EDUCATIONAL — scan only networks you own or have authorization to scan]
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"runtime"

	"github.com/NullAILab/37-self-hosted-shodan-clone/api"
	"github.com/NullAILab/37-self-hosted-shodan-clone/store"
)

func main() {
	addr := flag.String("addr", ":8080", "Listen address")
	flag.Parse()

	db := store.New()

	// Templates live next to the binary / in the repo root's templates/ dir.
	_, thisFile, _, _ := runtime.Caller(0)
	templateDir := filepath.Join(filepath.Dir(thisFile), "templates")

	srv, err := api.New(db, templateDir)
	if err != nil {
		log.Fatalf("failed to create server: %v", err)
	}

	fmt.Printf("Shodan Clone listening on http://localhost%s\n", *addr)
	fmt.Println("POST /api/scan   {\"cidr\":\"192.168.1.0/24\",\"ports\":[22,80,443]}")
	fmt.Println("GET  /api/search?q=port:22")
	fmt.Println("GET  /api/host/<ip>")
	fmt.Println("GET  /api/stats")

	if err := http.ListenAndServe(*addr, srv); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
