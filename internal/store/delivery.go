package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RsNest/auditdsec/internal/delivery"
)

// DeliveryDays lists retained journal generations, for pruning intake receipts.
func (s *Store) DeliveryDays() (map[string]bool, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, eventsDirName))
	if err != nil {
		return nil, err
	}
	days := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		day := strings.TrimSuffix(e.Name(), ".jsonl")
		if _, err := time.Parse(dayLayout, day); err == nil {
			days[day] = true
		}
	}
	return days, nil
}

// RecoverDeliveryPlans streams committed records after each durable receipt.
// Legacy records advance intake without generating retrospective notifications.
// No store lock is held while the callback waits for critical queue capacity.
func (s *Store) RecoverDeliveryPlans(cursors map[string]int64, accept func(delivery.Position, delivery.Plan) error) error {
	entries, err := os.ReadDir(filepath.Join(s.dir, eventsDirName)) // sorted by filename
	if err != nil {
		return err
	}
	for _, entry := range entries {
		day := strings.TrimSuffix(entry.Name(), ".jsonl")
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		if _, err := time.Parse(dayLayout, day); err != nil {
			continue
		}
		if err := s.recoverDay(day, cursors[day], accept); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) recoverDay(day string, offset int64, accept func(delivery.Position, delivery.Plan) error) error {
	f, err := os.Open(filepath.Join(s.dir, eventsDirName, day+".jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if offset < 0 || offset > fi.Size() {
		return errors.New("store: delivery receipt is beyond its journal")
	}
	if _, err = f.Seek(offset, io.SeekStart); err != nil {
		return err
	}
	r := bufio.NewReaderSize(f, 64<<10)
	var line []byte
	for {
		part, err := r.ReadSlice('\n')
		if len(line)+len(part) > maxJournalLine {
			return errors.New("store: oversized delivery journal record")
		}
		line = append(line, part...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF {
			return nil
		} // partial tail is not committed
		if err != nil {
			return err
		}
		var record journalRecord
		if err = json.Unmarshal(line, &record); err != nil {
			return fmt.Errorf("store: corrupt delivery journal %s at %d", day, offset)
		}
		end := offset + int64(len(line))
		plan := delivery.Plan{}
		if record.Plan != nil {
			plan = *record.Plan
		}
		if err = accept(delivery.Position{Day: day, Start: offset, End: end}, plan); err != nil {
			return err
		}
		offset = end
		line = nil
	}
}

// AppendDeliveryNotice journals a notification with no UI event. Ban notices
// stay separate from detection; their recipients and payload survive a restart.
func (s *Store) AppendDeliveryNotice(plan delivery.Plan) (delivery.Position, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeErr != nil {
		return delivery.Position{}, s.writeErr
	}
	now := s.now()
	f, err := s.fileFor(now)
	if err != nil {
		return delivery.Position{}, err
	}
	raw, err := json.Marshal(journalRecord{Plan: &plan})
	if err != nil {
		return delivery.Position{}, err
	}
	if len(raw)+1 > maxJournalLine {
		return delivery.Position{}, errors.New("store: oversized notification notice")
	}
	start, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return delivery.Position{}, err
	}
	_, err = f.Write(append(raw, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if err != nil {
		s.writeErr = err
		return delivery.Position{}, err
	}
	return delivery.Position{Day: now.UTC().Format(dayLayout), Start: start, End: start + int64(len(raw)+1)}, nil
}
