// Command auditdsec reads the Linux audit log, explains what happens on the
// host in plain language and reports it to Telegram.
//
// Subcommands:
//
//	auditdsec run [-config FILE]     follow the audit log (the default)
//	auditdsec check-config [-config] load the settings and report problems
//	auditdsec explain KIND [-lang]   explain one kind of event
//	auditdsec version                print the build version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/RsNest/auditdsec/internal/action"
	"github.com/RsNest/auditdsec/internal/config"
	"github.com/RsNest/auditdsec/internal/i18n"
	"github.com/RsNest/auditdsec/internal/logging"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/notify/telegram"
	"github.com/RsNest/auditdsec/internal/pipeline"
	"github.com/RsNest/auditdsec/internal/store"
)

// Set with -ldflags at build time; see the Makefile.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// defaultConfigPath is used when it exists and no path was given.
const defaultConfigPath = "/etc/auditdsec/auditdsec.yaml"

// shutdownGrace is how long the agent waits for its goroutines to finish.
const shutdownGrace = 10 * time.Second

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "auditdsec: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "run":
		return cmdRun(args)
	case "check-config":
		return cmdCheckConfig(args)
	case "explain":
		return cmdExplain(args)
	case "version":
		fmt.Printf("auditdsec %s (commit %s, built %s, %s)\n", version, commit, date, runtime.Version())
		return nil
	case "help", "-h", "--help":
		usage(os.Stdout)
		return nil
	default:
		usage(os.Stderr)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `auditdsec — auditd in plain language, with Telegram alerts

Usage:
  auditdsec run [-config FILE]       follow the audit log (the default command)
  auditdsec check-config [-config F] load the settings and report problems
  auditdsec explain KIND [-lang ru]  explain one kind of event
  auditdsec version                  print the build version

Environment (overrides the file):
  AUDITDSEC_CONFIG        path to the configuration file
  AUDITDSEC_TG_TOKEN      Telegram bot token
  AUDITDSEC_TG_CHAT_ID    allowed chat ids, comma separated
  AUDITDSEC_PROFILE       simple or pro
  AUDITDSEC_LANG          ru or en
  AUDITDSEC_AUDIT_LOG     path to audit.log
  AUDITDSEC_STATE_DIR     where state is kept
  AUDITDSEC_LOG_FILE      the agent's own log file
  AUDITDSEC_LOG_LEVEL     debug, info, warn or error
  AUDITDSEC_MIN_SEVERITY  info, warn or critical
  AUDITDSEC_RETENTION_DAYS how long events are kept
`)
}

// configPath resolves the flag, the environment and the default location, in
// that order. A missing default file is not an error: the agent can run on
// environment variables alone, which is how the container is meant to work.
func configPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if v := os.Getenv("AUDITDSEC_CONFIG"); v != "" {
		return v
	}
	if _, err := os.Stat(defaultConfigPath); err == nil {
		return defaultConfigPath
	}
	return ""
}

func cmdCheckConfig(args []string) error {
	fs := flag.NewFlagSet("check-config", flag.ContinueOnError)
	path := fs.String("config", "", "path to the configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(configPath(*path))
	if err != nil {
		return err
	}
	src := configPath(*path)
	if src == "" {
		src = "(no file, environment only)"
	}
	fmt.Printf("configuration source: %s\n\n%s\nThe configuration is valid.\n", src, cfg.Redacted())
	return nil
}

func cmdExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	langFlag := fs.String("lang", os.Getenv("AUDITDSEC_LANG"), "language: ru or en")
	if err := fs.Parse(args); err != nil {
		return err
	}
	lang, err := i18n.ParseLang(*langFlag)
	if err != nil {
		return err
	}

	kinds := make([]string, 0, len(model.AllKinds))
	for _, k := range model.AllKinds {
		kinds = append(kinds, string(k))
	}
	if fs.NArg() == 0 {
		fmt.Printf("Usage: auditdsec explain KIND\nKinds: %s\n", strings.Join(kinds, ", "))
		return nil
	}
	kind := model.Kind(strings.ToLower(fs.Arg(0)))
	if !model.ValidKind(kind) {
		return fmt.Errorf("unknown event kind %q (kinds: %s)", fs.Arg(0), strings.Join(kinds, ", "))
	}
	fmt.Printf("%s\n\n%s\n", kind, i18n.T(lang, "explain."+string(kind), nil))
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	path := fs.String("config", "", "path to the configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(configPath(*path))
	if err != nil {
		return err
	}

	log, closer, err := logging.Setup(logging.Options{
		File:       cfg.Log.File,
		Level:      cfg.Log.Level,
		MaxSizeMB:  cfg.Log.MaxSizeMB,
		MaxBackups: cfg.Log.MaxBackups,
		Stdout:     cfg.Log.Stdout,
	})
	if err != nil {
		return err
	}
	if closer != nil {
		defer closer.Close()
	}

	host := cfg.Host
	if host == "" {
		if h, err := os.Hostname(); err == nil {
			host = h
		} else {
			host = "unknown"
		}
	}

	st, err := store.Open(store.Options{
		Dir:           cfg.StateDir,
		MaxRecent:     cfg.Store.MaxRecent,
		RetentionDays: cfg.Store.RetentionDays,
	})
	if err != nil {
		return err
	}
	defer st.Close()

	started := time.Now()
	quietFrom, quietTo, _ := cfg.QuietHours()
	bot, err := telegram.New(telegram.Options{
		Token:         cfg.Telegram.Token,
		ChatIDs:       cfg.Telegram.ChatIDs,
		APIBase:       cfg.Telegram.APIBase,
		Lang:          cfg.Language(),
		Host:          host,
		Profile:       cfg.Profile,
		Store:         st,
		Logger:        log,
		Started:       started,
		MinSeverity:   cfg.MinSeverity(),
		DedupWindow:   cfg.Telegram.DedupWindow,
		RatePerMinute: cfg.Telegram.RatePerMinute,
		QuietFrom:     quietFrom,
		QuietTo:       quietTo,
	})
	if err != nil {
		return err
	}

	pl, err := pipeline.New(pipeline.Options{
		AuditLog:         cfg.AuditLog,
		StateDir:         cfg.StateDir,
		Host:             host,
		ReadFromStart:    cfg.ReadFromStart,
		HeartbeatEnabled: cfg.Heartbeat.Enabled,
		HeartbeatEvery:   cfg.Heartbeat.CheckEvery,
		HeartbeatStale:   cfg.Heartbeat.StaleAfter,
		Store:            st,
		Notifier:         bot,
		Logger:           log,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("auditdsec starting",
		"version", version, "host", host, "profile", cfg.Profile, "lang", string(cfg.Language()),
		"audit_log", cfg.AuditLog, "state_dir", cfg.StateDir,
		"min_severity", cfg.Telegram.MinSeverity,
		"banner", action.NoopBanner{}.Name(), "detector", "none (v0.2)")

	if cfg.Telegram.StartupNotice {
		if err := bot.SendStartupNotice(ctx); err != nil {
			// A bad token or chat id is the most common install mistake, and
			// the agent would otherwise sit there looking healthy.
			log.Error("cannot reach Telegram; check the token and the chat id", "error", err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		if err := bot.RunBot(ctx); err != nil {
			log.Error("the bot stopped", "error", err)
		}
	}()
	go func() {
		defer wg.Done()
		bot.RunGrouper(ctx)
	}()
	runErr := make(chan error, 1)
	go func() {
		defer wg.Done()
		runErr <- pl.Run(ctx)
	}()

	<-ctx.Done()
	stop() // restore the default handler, so a second signal kills at once
	log.Info("shutting down")

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(shutdownGrace):
		log.Warn("some tasks did not stop in time", "grace", shutdownGrace)
	}

	select {
	case err := <-runErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	default:
	}
	return nil
}
