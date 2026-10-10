package store

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/RsNest/auditdsec/internal/model"
)

const maxJournalLine = 32 << 20
const recentIDs = 4096
const bloomBytes = 1 << 20

// The fixed-size Bloom filter only rules out IDs. Positive matches are checked
// against the journal, so hash collisions cannot silently discard an event.
// At most two day indexes are cached; memory does not grow with retained history.
type eventIndex struct {
	bits []byte
	ids  map[string]struct{}
	ring []string
	next int
}

func bloomPositions(id string) [4]uint32 {
	h := sha256.Sum256([]byte(id))
	var p [4]uint32
	for i := range p {
		p[i] = binary.LittleEndian.Uint32(h[i*4:]) % (bloomBytes * 8)
	}
	return p
}

func (i *eventIndex) add(id string) {
	if id == "" {
		return
	}
	for _, p := range bloomPositions(id) {
		i.bits[p/8] |= 1 << (p % 8)
	}
	if _, ok := i.ids[id]; ok {
		return
	}
	delete(i.ids, i.ring[i.next])
	i.ring[i.next] = id
	i.next = (i.next + 1) % len(i.ring)
	i.ids[id] = struct{}{}
}

// Legacy rows have no event ID. Match their exact retained evidence on the
// conservative migration replay, so an upgrade does not resend old alerts.
func legacyKey(ev model.Event) string {
	if ev.Raw == "" {
		return ""
	}
	return fmt.Sprintf("legacy:%x", sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s", ev.Time.UnixNano(), ev.Kind, ev.Raw))))
}

func (s *Store) indexFor(day string) (*eventIndex, error) {
	if i := s.indexes[day]; i != nil {
		return i, nil
	}
	i := &eventIndex{bits: make([]byte, bloomBytes), ids: map[string]struct{}{}, ring: make([]string, recentIDs)}
	if err := s.walkDay(day, func(ev model.Event) bool {
		if ev.ID != "" {
			i.add(ev.ID)
		} else {
			i.add(legacyKey(ev))
		}
		return true
	}); err != nil {
		return nil, err
	}
	for len(s.indexOrder) >= 2 {
		delete(s.indexes, s.indexOrder[0])
		s.indexOrder = s.indexOrder[1:]
	}
	s.indexes[day] = i
	s.indexOrder = append(s.indexOrder, day)
	return i, nil
}

func (s *Store) containsEvent(i *eventIndex, day, id string) (bool, error) {
	if _, ok := i.ids[id]; ok {
		return true, nil
	}
	for _, p := range bloomPositions(id) {
		if i.bits[p/8]&(1<<(p%8)) == 0 {
			return false, nil
		}
	}
	found := false
	err := s.walkDay(day, func(ev model.Event) bool {
		if ev.ID == id || (ev.ID == "" && legacyKey(ev) == id) {
			found = true
			return false
		}
		return true
	})
	return found, err
}

func (s *Store) walkDay(day string, fn func(model.Event) bool) error {
	f, err := os.Open(filepath.Join(s.dir, eventsDirName, day+".jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64*1024)
	var line []byte
	discard := false
	for {
		part, err := r.ReadSlice('\n')
		if !discard {
			if len(line)+len(part) > maxJournalLine {
				discard = true
				line = nil
			} else {
				line = append(line, part...)
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF {
			return nil
		} // a newline is the record commit marker
		if err != nil {
			return err
		}
		if !discard {
			var ev model.Event
			if json.Unmarshal(line, &ev) == nil && ev.Kind != "" {
				if !fn(ev) {
					return nil
				}
			}
		}
		line, discard = nil, false
	}
}

// A torn last append must be removed before writing another record, otherwise
// the next valid JSON object would be concatenated to an unreadable fragment.
func repairJournalTail(f *os.File) error {
	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return err
	}
	end := fi.Size()
	var last [1]byte
	if _, err := f.ReadAt(last[:], end-1); err != nil {
		return err
	}
	if last[0] == '\n' {
		return nil
	}
	buf := make([]byte, 64*1024)
	for end > 0 {
		start := end - int64(len(buf))
		if start < 0 {
			start = 0
		}
		n, err := f.ReadAt(buf[:end-start], start)
		if err != nil && err != io.EOF {
			return err
		}
		for i := n - 1; i >= 0; i-- {
			if buf[i] == '\n' {
				if err := f.Truncate(start + int64(i) + 1); err != nil {
					return err
				}
				return f.Sync()
			}
		}
		end = start
	}
	if err := f.Truncate(0); err != nil {
		return fmt.Errorf("repair journal tail: %w", err)
	}
	return f.Sync()
}
