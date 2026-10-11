package update

import (
	"strconv"
	"strings"
	"time"
)

// States of the comparison.
const (
	StateUpToDate         = "up_to_date"
	StateAvailable        = "available"
	StateUnknownInstalled = "unknown_installed" // the installed build cannot be placed in the published history
	StateUnsupportedArch  = "unsupported_arch"
	StateIncomplete       = "incomplete" // the newest publication has no usable image
)

// Installed is what this copy knows about itself.
type Installed struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
	Channel string `json:"channel"`
}

// DefaultChannel picks the channel when none is configured: a tagged release
// follows stable, a build of the main branch follows main.
func DefaultChannel(version string) string {
	if _, ok := parseSemver(version); ok && !strings.Contains(version, "-dev") && !strings.Contains(version, "+") {
		return ChannelStable
	}
	return ChannelMain
}

// Result is the outcome of comparing the installed copy with a document.
type Result struct {
	State     string   `json:"state"`
	Latest    Build    `json:"latest"`
	Entries   []Entry  `json:"entries"`   // newest first: what changed between the installed build and the latest
	Truncated bool     `json:"truncated"` // the installed build is older than the published history
	Breaking  []Text   `json:"breaking"`
	Requires  Requires `json:"requires"` // the strictest of the entries
	Message   string   `json:"message,omitempty"`
}

type semver struct {
	major, minor, patch int
	pre                 string
}

func parseSemver(v string) (semver, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	pre := ""
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v, pre = v[:i], v[i+1:]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	var n [3]int
	for i, p := range parts {
		x, err := strconv.Atoi(p)
		if err != nil || x < 0 {
			return semver{}, false
		}
		n[i] = x
	}
	return semver{n[0], n[1], n[2], pre}, true
}

// less reports a < b: numeric by part, and a pre-release before its release.
func (a semver) less(b semver) bool {
	switch {
	case a.major != b.major:
		return a.major < b.major
	case a.minor != b.minor:
		return a.minor < b.minor
	case a.patch != b.patch:
		return a.patch < b.patch
	}
	return a.pre != "" && b.pre == ""
}

func archSupported(b Build, arch string) bool {
	img, ok := b.Images["auditdsec"]
	if !ok {
		return false
	}
	for _, p := range img.Platforms {
		if p == "linux/"+arch {
			return true
		}
	}
	return false
}

func migrationRank(m string) int {
	switch m {
	case "irreversible":
		return 2
	case "reversible":
		return 1
	}
	return 0
}

// Evaluate compares the installed copy with the document. It never concludes
// "up to date" from missing information, and it decides the order of main
// builds by their publication sequence, never by comparing commit IDs.
func Evaluate(inst Installed, m Metadata, arch string) Result {
	latest := m.Latest()
	res := Result{Latest: latest, Requires: Requires{Migration: "none"}}

	if !archSupported(latest, arch) {
		if _, ok := latest.Images["auditdsec"]; !ok {
			res.State, res.Message = StateIncomplete, "the newest publication has no image"
		} else {
			res.State, res.Message = StateUnsupportedArch, "the newest version is not published for this CPU architecture ("+arch+")"
		}
		return res
	}
	if inst.Commit != "" && inst.Commit == latest.Commit {
		res.State = StateUpToDate
		return res
	}

	idx := -1 // position of the installed build in the history; 0 would be the latest
	if shaRe.MatchString(inst.Commit) {
		for i, b := range m.Builds {
			if b.Commit == inst.Commit {
				idx = i
				break
			}
		}
	}

	switch m.Channel {
	case ChannelStable:
		cur, ok := parseSemver(inst.Version)
		lat, lok := parseSemver(latest.Version)
		switch {
		case !ok || !lok:
			res.State = StateUnknownInstalled
		case !cur.less(lat):
			res.State = StateUpToDate // equal, or newer than the latest release (a pre-release of the next one)
		case idx >= 0:
			res.State = StateAvailable
		default:
			// Releases are ordered by version; find the first build newer than
			// the installed one for the notes.
			res.State = StateAvailable
			idx = len(m.Builds)
			for i, b := range m.Builds {
				if v, vok := parseSemver(b.Version); vok && !cur.less(v) {
					idx = i
					break
				}
			}
			res.Truncated = idx == len(m.Builds)
		}
	default: // main: the publication order decides
		switch {
		case idx == 0:
			res.State = StateUpToDate
		case idx > 0:
			res.State = StateAvailable
		default:
			// Not in the history. Older than everything published is a fact
			// the build date can show; anything else cannot be placed.
			oldest, _ := time.Parse(time.RFC3339, m.Builds[len(m.Builds)-1].Published)
			built, err := time.Parse(time.RFC3339, inst.Date)
			if err == nil && !oldest.IsZero() && built.Before(oldest) {
				res.State, res.Truncated, idx = StateAvailable, true, len(m.Builds)
			} else {
				res.State = StateUnknownInstalled
			}
		}
	}
	if res.State == StateUpToDate {
		return res
	}

	// What changed between the installed build and the latest: the entries of
	// every build after the installed one, so skipped releases are included.
	end := idx
	if end < 0 || end > len(m.Builds) {
		end = len(m.Builds)
		res.Truncated = res.State == StateUnknownInstalled || res.Truncated
	}
	seen := map[string]bool{}
	for _, b := range m.Builds[:end] {
		for _, e := range b.Entries {
			if seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			res.Entries = append(res.Entries, e)
			res.Breaking = append(res.Breaking, e.Breaking...)
			if e.Requires.InstallerUpdate {
				res.Requires.InstallerUpdate = true
			}
			if migrationRank(e.Requires.Migration) > migrationRank(res.Requires.Migration) {
				res.Requires.Migration = e.Requires.Migration
			}
		}
	}
	if res.State == StateUnknownInstalled {
		// Do not present a long list as "what changed for you".
		res.Entries, res.Breaking = nil, nil
		res.Requires = Requires{Migration: "none"}
	}
	return res
}
