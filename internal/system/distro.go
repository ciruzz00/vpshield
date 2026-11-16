package system

import (
	"bufio"
	"os"
	"strings"
)

// Family groups distributions that share package manager, paths and service names.
type Family string

const (
	FamilyDebian  Family = "debian"
	FamilyRHEL    Family = "rhel"
	FamilyAlpine  Family = "alpine"
	FamilyArch    Family = "arch"
	FamilyUnknown Family = "unknown"
)

// Init is the service manager in use.
type Init string

const (
	InitSystemd Init = "systemd"
	InitOpenRC  Init = "openrc"
	InitUnknown Init = "unknown"
)

type Distro struct {
	ID        string
	Name      string
	Version   string
	VersionID string
	Family    Family
	Init      Init
}

// DetectDistro reads /etc/os-release and figures out the family and init system.
func DetectDistro() Distro {
	d := Distro{Family: FamilyUnknown, Init: InitUnknown}
	kv := parseOSRelease("/etc/os-release")
	if len(kv) == 0 {
		kv = parseOSRelease("/usr/lib/os-release")
	}
	d.ID = strings.ToLower(kv["ID"])
	d.Name = kv["PRETTY_NAME"]
	if d.Name == "" {
		d.Name = kv["NAME"]
	}
	d.Version = kv["VERSION"]
	d.VersionID = kv["VERSION_ID"]
	d.Family = familyFor(d.ID, strings.ToLower(kv["ID_LIKE"]))
	d.Init = detectInit()
	return d
}

func familyFor(id, idLike string) Family {
	match := func(words ...string) bool {
		for _, w := range words {
			if id == w {
				return true
			}
			for _, l := range strings.Fields(idLike) {
				if l == w {
					return true
				}
			}
		}
		return false
	}
	switch {
	case match("debian", "ubuntu", "raspbian", "linuxmint", "pop", "kali", "devuan"):
		return FamilyDebian
	case match("rhel", "centos", "rocky", "almalinux", "fedora", "ol", "amzn", "scientific"):
		return FamilyRHEL
	case match("alpine"):
		return FamilyAlpine
	case match("arch", "manjaro", "endeavouros", "artix"):
		return FamilyArch
	}
	return FamilyUnknown
}

func detectInit() Init {
	if st, err := os.Stat("/run/systemd/system"); err == nil && st.IsDir() {
		return InitSystemd
	}
	for _, p := range []string{"/sbin/openrc-run", "/sbin/openrc", "/usr/sbin/openrc"} {
		if _, err := os.Stat(p); err == nil {
			return InitOpenRC
		}
	}
	return InitUnknown
}

func parseOSRelease(path string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[k] = strings.Trim(v, `"'`)
	}
	return out
}

// MajorVersion returns the major part of VERSION_ID ("9.3" -> "9").
func (d Distro) MajorVersion() string {
	v, _, _ := strings.Cut(d.VersionID, ".")
	return v
}

// Packages maps a logical package name to the distro specific one(s).
// An empty slice means "nothing to install" (built in or not applicable).
func (d Distro) Packages(logical string) []string {
	table := map[string]map[Family][]string{
		"fail2ban": {
			FamilyDebian: {"fail2ban", "python3-systemd"},
			FamilyRHEL:   {"fail2ban"},
			FamilyAlpine: {"fail2ban"},
			FamilyArch:   {"fail2ban"},
		},
		"ufw":       {FamilyDebian: {"ufw"}, FamilyArch: {"ufw"}, FamilyAlpine: {"ufw"}, FamilyRHEL: {"ufw"}},
		"firewalld": {FamilyRHEL: {"firewalld"}, FamilyDebian: {"firewalld"}, FamilyArch: {"firewalld"}},
		"nftables":  {FamilyDebian: {"nftables"}, FamilyRHEL: {"nftables"}, FamilyAlpine: {"nftables"}, FamilyArch: {"nftables"}},
		"cron": {
			FamilyDebian: {"cron"},
			FamilyRHEL:   {"cronie"},
			FamilyArch:   {"cronie"},
			FamilyAlpine: {}, // busybox crond
		},
		"semanage": {FamilyRHEL: {"policycoreutils-python-utils"}},
		"autoupdates": {
			FamilyDebian: {"unattended-upgrades", "apt-listchanges"},
			FamilyRHEL:   {"dnf-automatic"},
			FamilyArch:   {"pacman-contrib"},
		},
		"ss": {FamilyAlpine: {"iproute2-ss"}},
	}
	if m, ok := table[logical]; ok {
		return m[d.Family]
	}
	return []string{logical}
}

// Service returns the distro specific service name for a logical service.
func (d Distro) Service(logical string) string {
	switch logical {
	case "sshd":
		if d.Family == FamilyDebian {
			return "ssh"
		}
		return "sshd"
	case "cron":
		switch d.Family {
		case FamilyDebian:
			return "cron"
		case FamilyArch:
			return "cronie"
		default:
			return "crond"
		}
	}
	return logical
}
