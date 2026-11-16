package system

import (
	"sort"
	"strconv"
	"strings"
)

// Listener is a listening socket.
type Listener struct {
	Proto   string // tcp | udp
	Addr    string // bind address
	Port    int
	Process string
}

// Public reports whether the socket listens on all interfaces.
func (l Listener) Public() bool {
	switch l.Addr {
	case "0.0.0.0", "*", "::", "[::]", "":
		return true
	}
	return false
}

// Listeners returns listening TCP/UDP sockets using ss, falling back to netstat.
func (h *Host) Listeners() []Listener {
	if h.Has("ss") {
		out, err := h.Query("ss", "-Htulpn")
		if err == nil {
			return ParseSS(out)
		}
	}
	out, err := h.Query("netstat", "-tulpn")
	if err != nil {
		return nil
	}
	return ParseNetstat(out)
}

func splitHostPort(s string) (string, int) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, 0
	}
	p, _ := strconv.Atoi(s[i+1:])
	host := strings.Trim(s[:i], "[]")
	if j := strings.Index(host, "%"); j >= 0 { // 127.0.0.53%lo
		host = host[:j]
	}
	return host, p
}

// ParseSS parses `ss -Htulpn` output.
func ParseSS(out string) []Listener {
	var ls []Listener
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		proto := f[0]
		if proto != "tcp" && proto != "udp" {
			continue
		}
		if proto == "tcp" && f[1] != "LISTEN" {
			continue
		}
		host, port := splitHostPort(f[4])
		l := Listener{Proto: proto, Addr: host, Port: port}
		if len(f) >= 7 {
			if i := strings.Index(f[6], `(("`); i >= 0 {
				rest := f[6][i+3:]
				if j := strings.Index(rest, `"`); j >= 0 {
					l.Process = rest[:j]
				}
			}
		}
		ls = append(ls, l)
	}
	return dedupe(ls)
}

// ParseNetstat parses `netstat -tulpn` (busybox and net-tools).
func ParseNetstat(out string) []Listener {
	var ls []Listener
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		proto := strings.TrimRight(f[0], "6")
		if proto != "tcp" && proto != "udp" {
			continue
		}
		if proto == "tcp" && !strings.Contains(line, "LISTEN") {
			continue
		}
		host, port := splitHostPort(f[3])
		l := Listener{Proto: proto, Addr: host, Port: port}
		last := f[len(f)-1]
		if _, name, ok := strings.Cut(last, "/"); ok {
			l.Process = name
		}
		ls = append(ls, l)
	}
	return dedupe(ls)
}

func dedupe(ls []Listener) []Listener {
	seen := map[string]bool{}
	var out []Listener
	for _, l := range ls {
		k := l.Proto + l.Addr + strconv.Itoa(l.Port)
		if seen[k] || l.Port == 0 {
			continue
		}
		seen[k] = true
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port == out[j].Port {
			return out[i].Proto < out[j].Proto
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// IsListening reports whether something listens on the TCP port.
func (h *Host) IsListening(port int) bool {
	for _, l := range h.Listeners() {
		if l.Proto == "tcp" && l.Port == port {
			return true
		}
	}
	return false
}
