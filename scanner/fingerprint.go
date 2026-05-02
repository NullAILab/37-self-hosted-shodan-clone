// Package scanner provides TCP port scanning and service fingerprinting.
//
// [EDUCATIONAL — scan only networks you own or have explicit authorization to scan]
package scanner

import (
	"strings"
)

// KnownPorts maps well-known port numbers to service names.
var KnownPorts = map[int]string{
	21:   "ftp",
	22:   "ssh",
	23:   "telnet",
	25:   "smtp",
	53:   "dns",
	80:   "http",
	110:  "pop3",
	143:  "imap",
	443:  "https",
	445:  "smb",
	3306: "mysql",
	5432: "postgresql",
	6379: "redis",
	8080: "http-alt",
	8443: "https-alt",
	9200: "elasticsearch",
	27017: "mongodb",
}

// IdentifyService returns a human-readable service name by inspecting the
// banner text first, then falling back to well-known port mappings.
func IdentifyService(port int, banner string) string {
	bl := strings.ToLower(strings.TrimSpace(banner))

	switch {
	case strings.HasPrefix(bl, "ssh-"):
		return "ssh"
	case strings.HasPrefix(bl, "http/"):
		return "http"
	case strings.HasPrefix(bl, "220 ") && strings.Contains(bl, "ftp"):
		return "ftp"
	case strings.HasPrefix(bl, "220 ") && (strings.Contains(bl, "smtp") || strings.Contains(bl, "esmtp") || strings.Contains(bl, "mail")):
		return "smtp"
	case strings.HasPrefix(bl, "220 "):
		return "ftp-or-smtp"
	case strings.Contains(bl, "redis") || strings.HasPrefix(bl, "+pong") || strings.HasPrefix(bl, "-err"):
		return "redis"
	case strings.Contains(bl, "mysql") || strings.HasPrefix(bl, "\x4a\x00\x00"):
		return "mysql"
	case strings.Contains(bl, "postgresql") || strings.HasPrefix(bl, "e\x00\x00\x00"):
		return "postgresql"
	case strings.Contains(bl, "mongodb"):
		return "mongodb"
	case strings.Contains(bl, "elasticsearch"):
		return "elasticsearch"
	}

	if name, ok := KnownPorts[port]; ok {
		return name
	}
	return "unknown"
}

// ExtractVersion attempts to pull a version string from common banner formats.
func ExtractVersion(service, banner string) string {
	if banner == "" {
		return ""
	}
	bl := strings.TrimSpace(banner)
	switch service {
	case "ssh":
		// "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
		parts := strings.SplitN(bl, " ", 2)
		if len(parts) > 0 {
			return strings.TrimPrefix(parts[0], "SSH-2.0-")
		}
	case "http", "http-alt", "https", "https-alt":
		// "HTTP/1.1 200 OK\r\nServer: nginx/1.24"
		for _, line := range strings.Split(bl, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), "server:") {
				return strings.TrimSpace(line[7:])
			}
		}
	case "ftp":
		// "220 ProFTPD 1.3.8 Server"
		parts := strings.Fields(bl)
		if len(parts) > 1 {
			return strings.Join(parts[1:], " ")
		}
	case "smtp":
		// "220 mail.example.com ESMTP Postfix 3.7.4"
		parts := strings.Fields(bl)
		if len(parts) > 1 {
			return strings.Join(parts[1:], " ")
		}
	}
	return ""
}
