package logging

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"
)

// archiveRe is what the janitor may delete: a rotated archive of one of this
// project's streams (agent.jsonl.2.gz, installer-commands.log.1). An active
// file, a file with another name and anything that is not a plain file are
// never matched.
var archiveRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*\.(jsonl|log)\.[0-9]+(\.gz)?$`)

// SweepOptions says what the directory may hold.
type SweepOptions struct {
	Dir         string
	MaxAge      time.Duration // 0: no age limit
	BudgetBytes int64         // 0: no size limit
	Now         time.Time     // zero: time.Now()
}

// Sweep removes archives older than MaxAge, then the oldest remaining archives
// until the whole directory (active files included) is within BudgetBytes. It
// returns what it removed. It never removes an active file: if those alone
// exceed the budget, the budget stays exceeded and the sizes of the files are
// bounded by their own rotation.
func Sweep(o SweepOptions) ([]string, error) {
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	entries, err := os.ReadDir(o.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	type file struct {
		name    string
		size    int64
		mod     time.Time
		archive bool
	}
	var files []file
	var total int64
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		f := file{name: e.Name(), size: info.Size(), mod: info.ModTime(), archive: archiveRe.MatchString(e.Name())}
		files = append(files, f)
		total += f.size
	}
	var removed []string
	remove := func(f file) bool {
		if err := os.Remove(filepath.Join(o.Dir, f.name)); err != nil && !os.IsNotExist(err) {
			return false
		}
		removed = append(removed, f.name)
		total -= f.size
		return true
	}
	var keep []file
	for _, f := range files {
		if f.archive && o.MaxAge > 0 && now.Sub(f.mod) > o.MaxAge && remove(f) {
			continue
		}
		keep = append(keep, f)
	}
	if o.BudgetBytes > 0 && total > o.BudgetBytes {
		var archives []file
		for _, f := range keep {
			if f.archive {
				archives = append(archives, f)
			}
		}
		sort.Slice(archives, func(i, j int) bool { return archives[i].mod.Before(archives[j].mod) })
		for _, f := range archives {
			if total <= o.BudgetBytes {
				break
			}
			remove(f)
		}
	}
	return removed, nil
}

// MarkRunning writes a marker file next to the logs while the process runs and
// removes it on a clean exit. unclean is true when a marker from an earlier run
// was still there: that run was killed, ran out of memory or lost power, and
// the log will say so at the start of this one. Without a directory it does
// nothing.
func (l *Logs) MarkRunning() (unclean bool, stopped func()) {
	if l.o.Dir == "" {
		return false, func() {}
	}
	path := filepath.Join(l.o.Dir, l.o.Service+".running")
	if _, err := os.Stat(path); err == nil {
		unclean = true
	}
	body := fmt.Sprintf("pid=%d started=%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339))
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		return unclean, func() {}
	}
	return unclean, func() { _ = os.Remove(path) }
}

// StartJanitor sweeps the log directory now and then every interval until ctx
// ends. It does nothing without a directory.
func (l *Logs) StartJanitor(ctx context.Context, interval time.Duration) {
	if l.o.Dir == "" {
		return
	}
	opts := SweepOptions{Dir: l.o.Dir}
	if l.o.MaxAgeDays > 0 {
		opts.MaxAge = time.Duration(l.o.MaxAgeDays) * 24 * time.Hour
	}
	if l.o.BudgetMB > 0 {
		opts.BudgetBytes = int64(l.o.BudgetMB) << 20
	}
	run := func() {
		removed, err := Sweep(opts)
		if err != nil {
			l.Main.Warn("log directory cleanup failed", "event", "log_sweep_failed", "error", err.Error())
			return
		}
		if len(removed) > 0 {
			l.Main.Info("old log archives removed", "event", "log_sweep", "count", len(removed), slog.Any("files", removed))
		}
	}
	run()
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				run()
			}
		}
	}()
}
