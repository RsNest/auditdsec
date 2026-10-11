// Command auditdsec-ctl is the local control service of an auditdsec
// installation. It runs on the server, outside the agent's container, as the
// user who runs ./install.sh, and lets the web panel ask for a change of how
// the panel is reached without giving the agent root or the Docker socket.
//
// It does one thing: start ./install.sh with arguments built from validated,
// structured parameters (see internal/access), one change at a time, and report
// its progress. It has no endpoint that takes a command, a path or a script, and
// it listens only on a Unix socket protected by file permissions and a token.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/RsNest/auditdsec/internal/access"
	"github.com/RsNest/auditdsec/internal/logging"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "auditdsec-ctl:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("auditdsec-ctl", flag.ContinueOnError)
	dir := fs.String("dir", ".", "the installation directory (the one with install.sh)")
	runDir := fs.String("run-dir", "", "directory for the socket and the token (default DIR/.ctl)")
	stateDir := fs.String("state-dir", "", "directory for the task records (default DIR/.ctl/state)")
	mode := fs.String("socket-mode", "0660", "permissions of the socket, octal")
	logDir := fs.String("log-dir", os.Getenv("AUDITDSEC_LOG_DIR"), "central log directory (control.jsonl); empty: standard error only")
	if err := fs.Parse(args); err != nil {
		return err
	}
	root, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	if fi, err := os.Stat(filepath.Join(root, "install.sh")); err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("%s has no install.sh", root)
	}
	if *runDir == "" {
		*runDir = filepath.Join(root, ".ctl")
	}
	if *stateDir == "" {
		*stateDir = filepath.Join(*runDir, "state")
	}
	m, err := strconv.ParseUint(*mode, 8, 32)
	if err != nil || m&^0o666 != 0 {
		return errors.New("socket-mode must be an octal permission such as 0660")
	}
	if err := os.MkdirAll(*runDir, 0o750); err != nil {
		return err
	}
	token, err := loadOrCreateToken(filepath.Join(*runDir, "token"))
	if err != nil {
		return err
	}
	runner, err := access.NewRunner(root, *stateDir, nil)
	if err != nil {
		return err
	}
	sock := filepath.Join(*runDir, "ctl.sock")
	l, err := access.Listen(sock, os.FileMode(m))
	if err != nil {
		return err
	}
	logs, err := logging.Open(logging.Options{Dir: *logDir, Service: "control", Stdout: true, MaxSizeMB: 10, MaxBackups: 5, MaxAgeDays: 14, BudgetMB: 512})
	if err != nil {
		return err
	}
	defer logs.Close()
	log := logs.Main
	runner.Log = log
	log.Info("control service listening", "event", "start", "socket", sock, "installation", root)
	srv := &http.Server{Handler: access.ControlHandler(runner, token), ReadHeaderTimeout: 5 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// loadOrCreateToken keeps one random token in a private file. The agent reads
// the same file (the directory is mounted into it read-only).
func loadOrCreateToken(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		return string(trim(b)), nil
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(raw[:])
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o640); err != nil {
		return "", err
	}
	return tok, nil
}

func trim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}
