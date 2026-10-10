// Command auditdsec reads the Linux audit log, explains what happens on the
// host in plain language and reports it to Telegram.
//
// Subcommands:
//
//	auditdsec run [-config FILE]     follow the audit log (the default)
//	auditdsec check-config [-config] load the settings and report problems
//	auditdsec explain KIND [-lang]   explain one kind of event
//	auditdsec hash-password          hash a panel password for the config
//	auditdsec version                print the build version
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/RsNest/auditdsec/internal/action"
	"github.com/RsNest/auditdsec/internal/api"
	"github.com/RsNest/auditdsec/internal/config"
	"github.com/RsNest/auditdsec/internal/detect"
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

// hostnameFile is where docker-compose.yml mounts the host's /etc/hostname. In
// a container os.Hostname() returns the container id, so alerts would be
// labelled "a1b2c3d4e5f6" instead of naming the server they came from — which
// is useless the moment you watch more than one machine.
const hostnameFile = "/etc/host-hostname"

// buildBanner creates the configured firewall backend. It returns the banner
// for the pipeline and the same object as the bot's enforcer, or nil for both
// when no backend is configured.
func buildBanner(ctx context.Context, cfg *config.Config, log *slog.Logger) (action.Banner, telegram.Enforcer, error) {
	if !cfg.EnforcesBans() {
		return nil, nil, nil
	}
	switch cfg.Ban.Backend {
	case config.BanBackendNftables:
		n := action.NewNftables(action.NftablesOptions{
			Table:  cfg.Ban.Table,
			DryRun: cfg.Ban.DryRun,
			Logger: log,
		})
		if err := n.Ensure(ctx); err != nil {
			return nil, nil, fmt.Errorf("ban.backend=nftables: %w", err)
		}
		return n, n, nil
	default:
		return nil, nil, fmt.Errorf("ban.backend: %q is not implemented", cfg.Ban.Backend)
	}
}

// banCount reports how many times an address has been banned before, which is
// what the escalation ladder climbs.
func banCount(st *store.Store, ip string) int {
	for _, b := range st.Bans() {
		if b.IP == ip {
			return b.Count
		}
	}
	return 0
}

// resolveHost decides the name that appears in every alert: the configured one,
// then the host's own name if it was mounted in, then whatever the kernel says.
func resolveHost(configured, mounted string) string {
	if h := strings.TrimSpace(configured); h != "" {
		return h
	}
	if mounted != "" {
		if b, err := os.ReadFile(mounted); err == nil {
			if h := strings.TrimSpace(string(b)); h != "" {
				return h
			}
		}
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown"
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		var code exitCode
		if errors.As(err, &code) {
			os.Exit(int(code))
		}
		if err.Error() != "" {
			fmt.Fprintf(os.Stderr, "auditdsec: %v\n", err)
		}
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
	case "hash-password":
		return cmdHashPassword(args)
	case "net-check":
		return cmdNetCheck(args)
	case "port-plan":
		return cmdPortPlan(args)
	case "port-check":
		return cmdPortCheck(args)
	case "probe-listen":
		return cmdProbeListen(args)
	case "remote-check":
		return cmdRemoteCheck(args)
	case "reset-credentials":
		return cmdResetCredentials(args)
	case "check-site", "check-domain":
		return cmdCheckSite(args)
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
  auditdsec run [-config FILE] [-debug]
                                     follow the audit log (the default command)
  auditdsec check-config [-config F] load the settings and report problems
  auditdsec explain KIND [-lang ru]  explain one kind of event
  auditdsec hash-password [-stdin]   hash a panel password for the web panel
  auditdsec reset-credentials -yes   forget the panel login and password (local recovery)
  auditdsec net-check domain NAME | ip   does public DNS lead to this server? which public addresses does it have?
  auditdsec port-plan | port-check PORT  candidate ports for the panel / can this port be bound?
  auditdsec remote-check ...             ask a RemoteProbe provider to connect to this server from outside
  auditdsec check-site NAME|IP       can this address get a certificate?
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
  AUDITDSEC_DEBUG         1 turns on debug mode (and raises the log level)
  AUDITDSEC_LOG_LEVEL     debug, info, warn or error
  AUDITDSEC_MIN_SEVERITY  info, warn or critical
  AUDITDSEC_RETENTION_DAYS how long events are kept
  AUDITDSEC_WEB           1 turns the web panel on
  AUDITDSEC_WEB_LISTEN    address the panel listens on
  AUDITDSEC_WEB_LOGIN     panel login name
  AUDITDSEC_WEB_PASSWORD_HASH  panel password hash (hash-password)
  AUDITDSEC_WEB_PASSWORD  panel password in plain text, hashed at startup
  AUDITDSEC_WEB_TRUSTED_PROXIES  networks a reverse proxy may connect from
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

// cmdResetCredentials is the local way back when the saved panel login and
// password are lost or damaged: it removes them, and the next start of the
// panel offers first-time setup (admin / admin, then a forced change) again.
// Running it on the server is the proof of ownership; there is no web reset.
func cmdResetCredentials(args []string) error {
	fs := flag.NewFlagSet("reset-credentials", flag.ContinueOnError)
	path := fs.String("config", "", "path to the configuration file")
	yes := fs.Bool("yes", false, "do it without asking")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(configPath(*path))
	if err != nil {
		return err
	}
	if !*yes {
		return errors.New("this REMOVES the panel login and password (the panel returns to admin / admin with a forced change); add -yes to confirm")
	}
	if err := api.ResetCredentials(cfg.StateDir); err != nil {
		return fmt.Errorf("cannot reset: %w", err)
	}
	fmt.Fprintln(os.Stderr, "The saved panel login and password were removed. Restart the agent so it starts first-time setup.")
	return nil
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

// cmdHashPassword turns a password into the hash the config file holds, so the
// plain password is never stored. It reads from the terminal with echo off, so
// the password does not stay in the scrollback either, and asks twice because
// a typo in something you cannot see is otherwise only discovered at the sign-in
// screen.
func cmdHashPassword(args []string) error {
	fs := flag.NewFlagSet("hash-password", flag.ContinueOnError)
	stdin := fs.Bool("stdin", false, "read the password from standard input instead of the terminal")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("the password is not taken as an argument, because it would stay in the shell history;\n" +
			"run `auditdsec hash-password` and type it, or pipe it in with `-stdin`")
	}

	password, err := readPassword(*stdin)
	if err != nil {
		return err
	}
	if reasons := api.CheckPassword(password, ""); len(reasons) > 0 {
		return fmt.Errorf("the password is not acceptable (%s): use at least %d characters with a lower-case and an upper-case letter, and not a common password",
			strings.Join(reasons, ", "), api.MinPasswordRunes)
	}

	hash, err := api.HashPassword(password)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", hash)
	fmt.Fprintf(os.Stderr, "\nThis is the hash, not the password: it is safe to paste into a file.\n"+
		"  .env:          AUDITDSEC_WEB_PASSWORD_HASH=<the line above>\n"+
		"  auditdsec.yaml: web.password_hash: \"<the line above>\"\n")
	return nil
}

func readPassword(fromStdin bool) (string, error) {
	in := bufio.NewReader(os.Stdin)
	readLine := func() (string, error) {
		line, err := in.ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("cannot read the password: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	if fromStdin {
		return readLine()
	}

	var first, second string
	var readErr error
	prompt := func() {
		fmt.Fprint(os.Stderr, "password: ")
		first, readErr = readLine()
		fmt.Fprintln(os.Stderr)
		if readErr != nil {
			return
		}
		fmt.Fprint(os.Stderr, "again: ")
		second, readErr = readLine()
		fmt.Fprintln(os.Stderr)
	}

	if !withoutEcho(os.Stdin.Fd(), prompt) {
		// Not a terminal: something is piping the password in. Read one line
		// and do not ask again, which would consume the next line of input.
		return readLine()
	}
	if readErr != nil {
		return "", readErr
	}
	if first != second {
		return "", fmt.Errorf("the two passwords do not match")
	}
	return first, nil
}

// printPanelBanner says where the panel is, in the form the person will type.
func printPanelBanner(w io.Writer, cfg *config.Config, setup string) {
	fmt.Fprintf(w, "\n  panel:  %s\n", cfg.PanelURL())
	switch setup {
	case api.StateBootstrap:
		fmt.Fprintf(w, "  first sign-in:  admin / admin  (it opens only the screen where the owner chooses a login and password)\n")
	case api.StateLocked:
		fmt.Fprintf(w, "  sign-in is STOPPED: the saved credentials cannot be used; see the log above\n")
	default:
		fmt.Fprintf(w, "  sign in with the login and password chosen at setup\n")
	}
	if cfg.PanelIsLoopbackOnly() {
		_, port, err := net.SplitHostPort(cfg.Web.Listen)
		if err != nil {
			port = "9477"
		}
		fmt.Fprintf(w, "\n  It listens on this machine only. From your own computer:\n"+
			"    ssh -L %s:127.0.0.1:%s %s@this-server\n"+
			"  then open %s there.\n"+
			"  To put it on a domain or this server's address instead, run ./install.sh.\n",
			port, port, currentUser(), cfg.PanelURL())
	}
	fmt.Fprintln(w)
}

func currentUser() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "root"
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	path := fs.String("config", "", "path to the configuration file")
	debug := fs.Bool("debug", false, "log every line read, every dropped record and every alert decision")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(configPath(*path))
	if err != nil {
		return err
	}
	// The flag is the most immediate of the three switches, so it wins — but
	// only when it was actually given, otherwise -debug=false would silently
	// override `debug: true` in the file.
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "debug" {
			cfg.Debug = *debug
			if cfg.Debug {
				cfg.Log.Level = "debug"
			}
		}
	})

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

	host := resolveHost(cfg.Host, hostnameFile)
	log.Debug("host name resolved", "host", host, "configured", cfg.Host != "")

	st, err := store.Open(store.Options{
		Dir:           cfg.StateDir,
		MaxRecent:     cfg.Store.MaxRecent,
		RetentionDays: cfg.Store.RetentionDays,
	})
	if err != nil {
		return err
	}
	defer st.Close()

	// The banner comes first: the bot and the pipeline both need it, and a
	// firewall backend that cannot be set up must stop the agent rather than
	// let it pretend the host is defended.
	banner, enforcer, err := buildBanner(context.Background(), cfg, log)
	if err != nil {
		return err
	}

	started := time.Now()
	quietFrom, quietTo, _ := cfg.QuietHours()
	bot, err := telegram.NewManaged(telegram.Options{
		Token:         cfg.Telegram.Token,
		ChatIDs:       cfg.Telegram.ChatIDs,
		APIBase:       cfg.Telegram.APIBase,
		Lang:          cfg.Language(),
		Host:          host,
		Profile:       cfg.Profile,
		Store:         st,
		Logger:        log,
		Started:       started,
		Debug:         cfg.Debug,
		LogLevel:      cfg.Log.Level,
		Enforcing:     cfg.EnforcesBans(),
		Enforcer:      enforcer,
		MinSeverity:   cfg.MinSeverity(),
		DedupWindow:   cfg.Telegram.DedupWindow,
		RatePerMinute: cfg.Telegram.RatePerMinute,
		QuietFrom:     quietFrom,
		QuietTo:       quietTo,
	}, cfg.StateDir, cfg.Telegram.StartupNotice)
	if err != nil {
		return err
	}

	var detector detect.Detector
	if cfg.Detect.Enabled {
		bf := detect.NewBruteForce(detect.Options{
			Window:               cfg.Detect.Window,
			FailThreshold:        cfg.Detect.FailThreshold,
			SuccessAfterFailures: cfg.Detect.SuccessAfterFailures,
			MaxTracked:           cfg.Detect.MaxTracked,
			BanCount:             func(ip string) int { return banCount(st, ip) },
			Allowed:              st.IsAllowed,
			Host:                 host,
		})
		observedAt := time.Now()
		if err := st.WalkEvents(observedAt.Add(-cfg.Detect.Window), observedAt, func(ev model.Event) bool {
			bf.RestoreFailure(ev, observedAt)
			return true
		}); err != nil {
			return fmt.Errorf("restore brute-force history: %w", err)
		}
		detector = bf
	}

	pl, err := pipeline.New(pipeline.Options{
		AuditLog:                cfg.AuditLog,
		StateDir:                cfg.StateDir,
		Host:                    host,
		ReadFromStart:           cfg.ReadFromStart,
		HeartbeatEnabled:        cfg.Heartbeat.Enabled,
		HeartbeatEvery:          cfg.Heartbeat.CheckEvery,
		HeartbeatStale:          cfg.Heartbeat.StaleAfter,
		Debug:                   cfg.Debug,
		Detector:                detector,
		Banner:                  banner,
		AutoAllowlistFirstLogin: cfg.Ban.AutoAllowlist == config.AutoAllowFirstLogin,
		PanelURL:                panelCertURL(cfg),
		PanelCertTrust:          cfg.Web.CertCheck != "expiry",
		Store:                   st,
		Notifier:                bot,
		Logger:                  log,
	})
	if err != nil {
		return err
	}

	defer pl.Close()

	// /debug reports what only the pipeline knows, so it is attached once the
	// pipeline exists.
	bot.SetDiag(func() []telegram.DiagItem {
		items := pl.Diagnostics()
		out := make([]telegram.DiagItem, 0, len(items))
		for _, it := range items {
			out = append(out, telegram.DiagItem{Key: it.Key, Value: it.Value})
		}
		return out
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("auditdsec starting",
		"version", version, "host", host, "profile", cfg.Profile, "lang", string(cfg.Language()),
		"audit_log", cfg.AuditLog, "state_dir", cfg.StateDir,
		"min_severity", cfg.Telegram.MinSeverity, "debug", cfg.Debug,
		"detect", cfg.Detect.Enabled, "ban_backend", cfg.Ban.Backend,
		"auto_allowlist", cfg.Ban.AutoAllowlist)

	if cfg.Detect.Enabled && !cfg.EnforcesBans() {
		// Saying this plainly matters: the owner would otherwise believe the
		// agent is blocking attackers when it is only writing them down.
		log.Warn("ban decisions are recorded and reported but NOT applied on the host",
			"reason", "ban.backend is none",
			"how_to_enable", "see the README section on bans (needs NET_ADMIN and host networking)")
	}

	if cfg.Debug {
		log.Warn("debug mode is on: the log records every audit line, every ignored record and every alert decision",
			"log_file", cfg.Log.File,
			"turn_off", "remove AUDITDSEC_DEBUG (or debug: true) and restart")
	}

	// The panel, when it is switched on. It refuses to start without a
	// password, which is why this happens before anything else is launched.
	var panel *api.Server
	if cfg.Web.Enabled {
		panel, err = api.New(api.Options{
			Config: cfg, Store: st, Enforcer: enforcer, Runtime: pl, Telegram: bot,
			Host: host, Version: version, Started: started, Logger: log,
		})
		if err != nil {
			return err
		}
		log.Info("web panel enabled", "public_url", cfg.PanelURL(), "upstream_listen", cfg.Web.Listen,
			"setup", panel.SetupState(),
			"session_ttl", cfg.Web.SessionTTL, "trusted_proxies", cfg.Web.TrustedProxies)
		// The link is the one thing the person actually needs after
		// installing, and hunting for it in a log line of key=value pairs is
		// a poor way to find it.
		printPanelBanner(os.Stdout, cfg, panel.SetupState())
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		bot.Run(ctx)
	}()
	if panel != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := panel.ListenAndServe(ctx); err != nil {
				log.Error("the web panel stopped", "error", err)
			}
		}()
	}
	runErr := make(chan error, 1)
	go func() {
		defer wg.Done()
		err := pl.Run(ctx)
		runErr <- err
		if err != nil {
			stop()
		}
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

// panelCertURL is the link whose served certificate the agent watches: the
// public https URL of an enabled panel, unless the check is switched off.
func panelCertURL(cfg *config.Config) string {
	if !cfg.Web.Enabled || cfg.Web.CertCheck == "off" {
		return ""
	}
	if u := cfg.PanelURL(); strings.HasPrefix(u, "https://") {
		return u
	}
	return ""
}
