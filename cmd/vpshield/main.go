// vpshield - interactive hardening for internet facing Linux servers.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"vpshield/internal/audit"
	"vpshield/internal/fail2ban"
	"vpshield/internal/firewall"
	"vpshield/internal/sshd"
	"vpshield/internal/system"
	"vpshield/internal/tui"
)

var version = "dev" // set with -ldflags "-X main.version=v1.0.0"

const usage = `vpshield %s - harden internet facing Linux servers

Usage:
  vpshield [--dry-run]            start the TUI
  vpshield status                 one screen summary
  vpshield audit [--save] [--quiet]
                                  security report (--save writes /var/log/vpshield/audit-DATE.txt)
  vpshield confirm                keep a pending SSH change (cancel the automatic rollback)
  vpshield rollback --list        list snapshots
  vpshield rollback <snapshot>    restore a snapshot
  vpshield prune --days N         delete snapshots older than N days
  vpshield version

--dry-run shows every plan and logs the commands without changing anything.
`

func main() {
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		os.Exit(subcommand(os.Args[1], os.Args[2:]))
	}
	dry := flag.Bool("dry-run", false, "show what would change, change nothing")
	ver := flag.Bool("version", false, "print version")
	flag.Usage = func() { fmt.Fprintf(os.Stderr, usage, version) }
	flag.Parse()
	if *ver {
		fmt.Println(version)
		return
	}
	h := system.NewHost(*dry)
	if h.Distro.Family == system.FamilyUnknown {
		fmt.Fprintf(os.Stderr, "warning: unsupported distribution %q, some features will not work\n", h.Distro.ID)
		time.Sleep(1500 * time.Millisecond)
	}
	if err := tui.Run(h, system.LoadState()); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func needRoot() bool {
	if !system.IsRoot() {
		fmt.Fprintln(os.Stderr, "this command needs root (sudo vpshield ...)")
		return false
	}
	return true
}

func subcommand(name string, args []string) int {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	switch name {
	case "version":
		fmt.Println(version)
	case "help":
		fmt.Printf(usage, version)
	case "confirm":
		if !needRoot() {
			return 1
		}
		d := system.ActiveDeadman()
		h := system.NewHost(false)
		if d == nil {
			fmt.Println("no pending rollback")
			_ = h.DisarmDeadman() // clean leftovers anyway
			return 0
		}
		if err := h.DisarmDeadman(); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Printf("confirmed: change kept (rollback of %s cancelled)\n", d.SnapshotID)
	case "rollback":
		list := fs.Bool("list", false, "list snapshots")
		deadman := fs.Bool("deadman", false, "internal: fired by the dead-man switch")
		fs.Parse(reorder(args))
		if *list || fs.NArg() == 0 {
			snaps, err := system.ListSnapshots()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			for _, s := range snaps {
				fmt.Printf("%-20s %-17s %3d files  %s\n", s.ID, s.Created.Format("2006-01-02 15:04"), len(s.Entries), s.Label)
			}
			return 0
		}
		if !needRoot() {
			return 1
		}
		h := system.NewHost(false)
		if *deadman {
			system.ClearDeadmanMarker()
		}
		rep, err := h.Restore(fs.Arg(0))
		for _, l := range rep {
			fmt.Println(l)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	case "audit":
		save := fs.Bool("save", false, "save to /var/log/vpshield")
		quiet := fs.Bool("quiet", false, "no output")
		fs.Parse(args)
		h := system.NewHost(false)
		r := audit.Run(h, system.LoadState())
		if !*quiet {
			fmt.Print(r.Text())
		}
		if *save {
			p, err := r.Save()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			if !*quiet {
				fmt.Println("\nsaved to", p)
			}
		}
	case "status":
		h := system.NewHost(false)
		st := system.LoadState()
		fw := firewall.Detect(h, st)
		cur := sshd.Current(h)
		fmt.Printf("host      %s (%s, %s)\n", system.Hostname(), h.Distro.Name, h.Distro.Init)
		fmt.Printf("firewall  %s active=%v\n", fw.Name(), fw.Active())
		fmt.Printf("ssh       port=%d root=%s password=%v\n", cur.Port, cur.PermitRootLogin, cur.PasswordAuth)
		if fail2ban.Running(h) {
			all, _ := fail2ban.AllStatus(h)
			for _, j := range all {
				fmt.Printf("fail2ban  %-18s banned=%d total=%d\n", j.Name, j.CurBanned, j.TotBanned)
			}
		} else {
			fmt.Println("fail2ban  not running")
		}
		if d := system.ActiveDeadman(); d != nil {
			fmt.Printf("PENDING   automatic rollback of %s in %s (vpshield confirm)\n", d.SnapshotID, time.Until(d.Deadline).Round(time.Second))
		}
	case "prune":
		days := fs.Int("days", 30, "age in days")
		fs.Parse(args)
		if !needRoot() {
			return 1
		}
		n, err := system.PruneSnapshots(time.Duration(*days) * 24 * time.Hour)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("pruned %d snapshots\n", n)
	default:
		fmt.Fprintf(os.Stderr, usage, version)
		return 2
	}
	return 0
}

// reorder lets flags come after positional args (rollback <id> --deadman).
func reorder(args []string) []string {
	var flags, pos []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
		} else {
			pos = append(pos, a)
		}
	}
	return append(flags, pos...)
}
