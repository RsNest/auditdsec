package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// StateInfo is a read-only summary of a state directory, safe to take while the
// agent is running: it only reads, never locks or writes the live files.
type StateInfo struct {
	Exists            bool
	Modified          time.Time
	BansByState       map[string]int // active and historical records by observed state
	NoticesOwed       int
	Releases          int
	Allowlist         int
	DetectInitialized bool
	BacklogBytes      int64 // journal bytes the detector has not consumed
	BacklogDays       int
}

// InspectState reads state.json and the journal sizes under dir.
func InspectState(dir string) (StateInfo, error) {
	info := StateInfo{BansByState: map[string]int{}}
	path := filepath.Join(dir, stateFileName)
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return info, nil
	}
	if err != nil {
		return info, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return info, err
	}
	var p persisted
	if err := json.Unmarshal(data, &p); err != nil {
		return info, err
	}
	info.Exists, info.Modified = true, fi.ModTime()
	for _, b := range normalizeAll(p.Bans) {
		info.BansByState[b.State]++
		if b.NoticeDue {
			info.NoticesOwed++
		}
	}
	info.Releases, info.Allowlist = len(p.Releases), len(p.Allowlist)
	if p.Detect != nil && p.Detect.Initialized {
		info.DetectInitialized = true
		days, err := journalDays(dir)
		if err != nil {
			return info, err
		}
		for day, size := range days {
			if size > p.Detect.Cursors[day] {
				info.BacklogBytes += size - p.Detect.Cursors[day]
				info.BacklogDays++
			}
		}
	}
	return info, nil
}

func normalizeAll(m map[string]Ban) []Ban {
	out := make([]Ban, 0, len(m))
	for _, b := range m {
		out = append(out, normalizeBan(b))
	}
	return out
}
