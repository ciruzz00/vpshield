package system

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var SnapshotRoot = filepath.Join(StateDir, "backups")

// Snapshot is a set of files saved before a plan touched them, plus the
// commands needed to make the restored files effective again.
type Snapshot struct {
	ID      string          `json:"id"`
	Label   string          `json:"label"`
	Created time.Time       `json:"created"`
	Entries []SnapshotEntry `json:"entries"`
	Hooks   [][]string      `json:"hooks"` // run after restore, errors ignored
	dir     string
}

type SnapshotEntry struct {
	Path    string      `json:"path"`
	Existed bool        `json:"existed"`
	Mode    os.FileMode `json:"mode"`
	Symlink string      `json:"symlink,omitempty"`
}

// BeginSnapshot opens a new snapshot; every WriteFile/Backup until
// EndSnapshot lands in it.
func (h *Host) BeginSnapshot(label string) *Snapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	id := time.Now().Format("20060102-150405")
	// avoid collisions when two plans run within the same second
	for i := 1; Exists(filepath.Join(SnapshotRoot, id)); i++ {
		id = fmt.Sprintf("%s-%d", time.Now().Format("20060102-150405"), i)
	}
	h.snap = &Snapshot{ID: id, Label: label, Created: time.Now(), dir: filepath.Join(SnapshotRoot, id)}
	return h.snap
}

// EndSnapshot closes the active snapshot. Empty snapshots are discarded.
func (h *Host) EndSnapshot() *Snapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.snap
	h.snap = nil
	if s != nil && len(s.Entries) == 0 && len(s.Hooks) == 0 {
		os.RemoveAll(s.dir)
		return nil
	}
	return s
}

// CurrentSnapshot returns the active snapshot (may be nil).
func (h *Host) CurrentSnapshot() *Snapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.snap
}

// AddRestoreHook registers a command to run after this snapshot is restored.
func (h *Host) AddRestoreHook(cmd ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.snap == nil || h.DryRun {
		return
	}
	for _, c := range h.snap.Hooks {
		if strings.Join(c, " ") == strings.Join(cmd, " ") {
			return
		}
	}
	h.snap.Hooks = append(h.snap.Hooks, cmd)
	_ = h.snap.save()
}

// Backup saves path into the active snapshot (once per snapshot).
// With no active snapshot it is a no-op.
func (h *Host) Backup(path string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.snap
	if s == nil || h.DryRun {
		return nil
	}
	path = filepath.Clean(path)
	for _, e := range s.Entries {
		if e.Path == path {
			return nil
		}
	}
	e := SnapshotEntry{Path: path}
	st, err := os.Lstat(path)
	switch {
	case os.IsNotExist(err):
		e.Existed = false
	case err != nil:
		return err
	default:
		e.Existed = true
		e.Mode = st.Mode().Perm()
		if st.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			e.Symlink = target
		} else {
			if err := copyFile(path, filepath.Join(s.dir, "files", path), e.Mode); err != nil {
				return err
			}
		}
	}
	s.Entries = append(s.Entries, e)
	return s.save()
}

func (s *Snapshot) save() error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(filepath.Join(s.dir, "manifest.json"), b, 0o600)
}

func copyFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// ListSnapshots returns snapshots, newest first.
func ListSnapshots() ([]Snapshot, error) {
	ents, err := os.ReadDir(SnapshotRoot)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Snapshot
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		s, err := LoadSnapshot(e.Name())
		if err == nil {
			out = append(out, *s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out, nil
}

func LoadSnapshot(id string) (*Snapshot, error) {
	id = filepath.Base(id)
	if id == "." || id == ".." || id == "/" || id == "" {
		return nil, fmt.Errorf("invalid snapshot id")
	}
	dir := filepath.Join(SnapshotRoot, id)
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	s.dir = dir
	return &s, nil
}

// Restore puts every file of the snapshot back and runs its hooks.
// It deliberately does not open a new snapshot.
func (h *Host) Restore(id string) ([]string, error) {
	s, err := LoadSnapshot(id)
	if err != nil {
		return nil, err
	}
	var report []string
	if h.DryRun {
		for _, e := range s.Entries {
			report = append(report, "[dry-run] restore "+e.Path)
		}
		return report, nil
	}
	var firstErr error
	for i := len(s.Entries) - 1; i >= 0; i-- {
		e := s.Entries[i]
		var err error
		switch {
		case !e.Existed:
			err = os.Remove(e.Path)
			if os.IsNotExist(err) {
				err = nil
			}
			report = append(report, "removed "+e.Path)
		case e.Symlink != "":
			os.Remove(e.Path)
			err = os.Symlink(e.Symlink, e.Path)
			report = append(report, "relinked "+e.Path+" -> "+e.Symlink)
		default:
			err = copyFile(filepath.Join(s.dir, "files", e.Path), e.Path, e.Mode)
			if err == nil {
				err = os.Chmod(e.Path, e.Mode)
			}
			report = append(report, "restored "+e.Path)
		}
		if err != nil {
			report = append(report, "  error: "+err.Error())
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	for _, hk := range s.Hooks {
		if len(hk) == 0 {
			continue
		}
		out, err := exe(2*time.Minute, hk[0], hk[1:]...)
		line := "hook: " + CmdString(hk[0], hk[1:]...)
		if err != nil {
			line += "  (error: " + err.Error() + ")"
		} else if out != "" {
			line += "  -> " + lastLines(out, 1)
		}
		report = append(report, line)
	}
	h.logf("restored snapshot %s (%s)", s.ID, s.Label)
	return report, firstErr
}

// PruneSnapshots removes snapshots older than the given age.
func PruneSnapshots(olderThan time.Duration) (int, error) {
	snaps, err := ListSnapshots()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, s := range snaps {
		if time.Since(s.Created) > olderThan {
			if err := os.RemoveAll(filepath.Join(SnapshotRoot, s.ID)); err == nil {
				n++
			}
		}
	}
	return n, nil
}
