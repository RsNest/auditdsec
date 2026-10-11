package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/RsNest/auditdsec/internal/config"
)

// healthcheck is the container's health command. It asks the panel's own web
// server on the address it listens on, with no proxy, and succeeds only when
// that server answers. With the panel switched off there is nothing to ask
// and the agent is healthy as long as it runs. It uses the binary itself, so
// the minimal image needs neither curl nor a shell.
//
// It cannot see what is outside its own container (a proxy waiting for an
// address this container is not on): that is checked by the installer, which
// can look at Docker. See deploy-check and docs/ARCHITECTURE.md.
func cmdHealthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	path := fs.String("config", "", "path to the configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(configPath(*path))
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	if !cfg.Web.Enabled {
		return nil
	}
	addr := loopbackOf(cfg.Web.Listen)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/api/v1/setup/state", nil)
	if err != nil {
		return err
	}
	// No proxy: HTTP_PROXY must never stand between a container and itself.
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("healthcheck: the panel does not answer on %s: %w", addr, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: the panel answered %d on %s", resp.StatusCode, addr)
	}
	return nil
}

// loopbackOf turns a listen address into one a local client can dial.
func loopbackOf(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// composeConfig is the part of `docker compose config --format json` that
// decides whether the panel can work.
type composeConfig struct {
	Services map[string]composeService `json:"services"`
}

type composeService struct {
	Image       string            `json:"image"`
	NetworkMode string            `json:"network_mode"`
	Networks    map[string]any    `json:"networks"`
	Ports       []any             `json:"ports"`
	CapAdd      []string          `json:"cap_add"`
	GroupAdd    []string          `json:"group_add"`
	Environment map[string]string `json:"environment"`
	Healthcheck *struct {
		Test []string `json:"test"`
	} `json:"healthcheck"`
}

// DeployExpect is what the chosen way of reaching the panel requires of the
// final Compose configuration.
type DeployExpect struct {
	Mode         string // domain | ip | selfsigned | tunnel
	UpstreamPort string
	HTTPSPort    string
	Enforce      bool
	Control      bool
}

// CheckDeployment compares the resolved configuration with what the chosen
// access mode needs and returns one line per disagreement. The agent and the
// proxy reach each other on loopback, so both must share the host's network
// namespace; and nothing may publish the agent's own port.
func CheckDeployment(doc []byte, e DeployExpect) ([]string, error) {
	var cfg composeConfig
	if err := json.Unmarshal(doc, &cfg); err != nil {
		return nil, fmt.Errorf("not a Compose configuration: %w", err)
	}
	var p []string
	bad := func(format string, a ...any) { p = append(p, fmt.Sprintf(format, a...)) }

	agent, ok := cfg.Services["auditdsec"]
	if !ok {
		return []string{"the agent service (auditdsec) is not in the configuration"}, nil
	}
	upstream := "127.0.0.1:" + e.UpstreamPort
	if agent.Environment["AUDITDSEC_WEB"] != "1" {
		bad("the panel's web server is not switched on for the agent (AUDITDSEC_WEB=%q)", agent.Environment["AUDITDSEC_WEB"])
	}
	if got := agent.Environment["AUDITDSEC_WEB_LISTEN"]; got != upstream {
		bad("the agent would listen on %q, not on %s", got, upstream)
	}
	if agent.NetworkMode != "host" {
		bad("the agent is not in the host network (network_mode=%q): it would listen on %s inside its own network, where the proxy and this server cannot reach it", agent.NetworkMode, upstream)
	}
	if len(agent.Ports) > 0 {
		bad("the agent publishes ports (%d); its own port must stay on loopback", len(agent.Ports))
	}
	if agent.Healthcheck == nil || len(agent.Healthcheck.Test) < 3 || agent.Healthcheck.Test[len(agent.Healthcheck.Test)-1] != "healthcheck" {
		bad("the agent has no health check that asks the web server")
	}

	caddy, hasCaddy := cfg.Services["caddy"]
	certbot, hasCertbot := cfg.Services["certbot"]
	switch e.Mode {
	case "domain", "ip", "selfsigned":
		if !hasCaddy {
			bad("the proxy (caddy) is missing for mode %s", e.Mode)
			break
		}
		if caddy.NetworkMode != "host" {
			bad("the proxy is not in the host network (network_mode=%q)", caddy.NetworkMode)
		}
		if strings.TrimSpace(caddy.Environment["PANEL_SITE"]) == "" {
			bad("the proxy has no panel address: set PANEL_SITE in .env, or run ./install.sh (PANEL_DOMAIN is supported for older installations)")
		}
		if got := caddy.Environment["PANEL_UPSTREAM"]; got != upstream {
			bad("the proxy would send requests to %q, not to %s", got, upstream)
		}
		if e.HTTPSPort != "" && caddy.Environment["PANEL_HTTPS_PORT"] != e.HTTPSPort {
			bad("the proxy would listen on port %q, not on %s", caddy.Environment["PANEL_HTTPS_PORT"], e.HTTPSPort)
		}
		if len(caddy.Ports) > 0 {
			bad("the proxy publishes ports in addition to the host network")
		}
	case "tunnel":
		if hasCaddy {
			bad("a proxy (caddy) is configured although the mode is an SSH tunnel: nothing may be opened to the internet")
		}
	default:
		bad("unknown mode %q", e.Mode)
	}
	if e.Mode == "ip" && !hasCertbot {
		bad("the certificate renewal container (certbot) is missing for mode ip")
	}
	if e.Mode != "ip" && hasCertbot {
		bad("a certificate renewal container (certbot) is configured although the mode is %s", e.Mode)
	}
	if hasCertbot && certbot.NetworkMode != "host" {
		bad("certbot is not in the host network (network_mode=%q): it could not answer the challenge on port 80", certbot.NetworkMode)
	}

	hasNetAdmin := false
	for _, c := range agent.CapAdd {
		if c == "NET_ADMIN" {
			hasNetAdmin = true
		}
	}
	switch {
	case e.Enforce && (!hasNetAdmin || agent.Environment["AUDITDSEC_BAN_BACKEND"] != "nftables"):
		bad("blocking is on but the agent lacks NET_ADMIN or the nftables backend")
	case !e.Enforce && hasNetAdmin:
		bad("the agent has NET_ADMIN although blocking is off")
	}
	if e.Control != (len(agent.GroupAdd) > 0 && agent.Environment["AUDITDSEC_CTL_SOCKET"] != "") {
		if e.Control {
			bad("the control service is on but the agent has no link to it")
		} else {
			bad("the agent has a link to the control service although it is off")
		}
	}
	sort.Strings(p)
	return p, nil
}

// cmdDeployCheck reads `docker compose config --format json` on standard input
// and checks it (CheckDeployment). Exit status 0: consistent, 3: it is not.
func cmdDeployCheck(args []string) error {
	fs := flag.NewFlagSet("deploy-check", flag.ContinueOnError)
	var e DeployExpect
	fs.StringVar(&e.Mode, "mode", "", "domain, ip, selfsigned or tunnel")
	fs.StringVar(&e.UpstreamPort, "upstream-port", "9477", "the agent's own port on loopback")
	fs.StringVar(&e.HTTPSPort, "https-port", "", "the public HTTPS port (proxy modes)")
	fs.BoolVar(&e.Enforce, "enforce", false, "blocking with nftables is on")
	fs.BoolVar(&e.Control, "control", false, "the control service is linked")
	if err := fs.Parse(args); err != nil {
		return err
	}
	doc, err := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
	if err != nil {
		return err
	}
	problems, err := CheckDeployment(doc, e)
	if err != nil {
		fmt.Fprintln(os.Stderr, "deploy-check:", err)
		return exitCode(1)
	}
	for _, p := range problems {
		fmt.Println("PROBLEM|" + p)
	}
	if len(problems) > 0 {
		return exitCode(3)
	}
	fmt.Println("OK")
	return nil
}
