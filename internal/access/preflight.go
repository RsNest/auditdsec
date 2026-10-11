package access

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/RsNest/auditdsec/internal/netcheck"
)

// Check statuses. "unchecked" is a real answer: this check cannot be made from
// here and is made by the installer when the change is applied.
const (
	CheckOK        = "ok"
	CheckFailed    = "failed"
	CheckUnchecked = "unchecked"
)

// Check is one precondition of a change, with what is known about it.
type Check struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Text   string `json:"text"`
}

// Preflight is the preliminary look at a domain: public DNS compared with this
// server, and the conditions that cannot be known before the change is
// applied. A matching DNS is a precondition for a certificate, never a promise
// of one.
type Preflight struct {
	Domain   string    `json:"domain"`
	At       time.Time `json:"at"`
	A        []string  `json:"a"`
	AAAA     []string  `json:"aaaa"`
	Server   []string  `json:"server_addresses"` // the addresses this server is known to have
	DNSOK    bool      `json:"dns_ok"`
	Problems []string  `json:"problems,omitempty"`
	Notes    []string  `json:"notes,omitempty"`
	Checks   []Check   `json:"checks"`
	// Records are what to create at the DNS provider.
	Records []Record `json:"records"`
}

// Record is a DNS record the person has to have in place.
type Record struct {
	Type  string `json:"type"` // A or AAAA
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Deps are the outside facts a preflight needs. Tests replace them.
type Deps struct {
	Resolvers []netcheck.Resolver
	// Server describes this server's own addresses.
	Server   func(ctx context.Context) netcheck.Server
	Attempts int
	Wait     time.Duration
	Now      func() time.Time
}

// DefaultDeps asks three public resolvers and looks at this machine's
// interfaces and, as a hint, at the address an outside service sees.
func DefaultDeps() Deps {
	var rs []netcheck.Resolver
	for _, a := range netcheck.DefaultResolvers {
		rs = append(rs, netcheck.NewUDPResolver(a))
	}
	return Deps{
		Resolvers: rs, Attempts: 2, Wait: 3 * time.Second,
		Server: func(ctx context.Context) netcheck.Server {
			var s netcheck.Server
			s.Global, s.OnlyPrivate = netcheck.Describe(netcheck.LocalAddresses())
			s.Egress = netcheck.Egress(ctx, netcheck.EgressServices)
			return s
		},
		Now: time.Now,
	}
}

func strs(as []netip.Addr) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.String()
	}
	return out
}

// CheckDomain compares the domain's public DNS with this server and lists the
// other conditions honestly, as checked or not.
func CheckDomain(ctx context.Context, domain string, d Deps) (Preflight, error) {
	name, err := NormalizeDomain(domain)
	if err != nil {
		return Preflight{}, err
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	srv := netcheck.Server{}
	if d.Server != nil {
		srv = d.Server(ctx)
	}
	res := netcheck.LookupAll(ctx, name, d.Resolvers, max(d.Attempts, 1), d.Wait)
	v := netcheck.JudgeDomain(res, srv)

	p := Preflight{Domain: name, At: d.Now().UTC(), A: strs(res.V4), AAAA: strs(res.V6), DNSOK: v.OK, Problems: v.Problems, Notes: v.Notes}
	known := map[netip.Addr]bool{}
	var addrs []netip.Addr
	for _, group := range [][]netip.Addr{srv.Global, srv.Egress, srv.Claimed} {
		for _, a := range group {
			if !known[a] {
				known[a] = true
				addrs = append(addrs, a)
			}
		}
	}
	p.Server = strs(addrs)
	for _, a := range addrs {
		t := "A"
		if a.Is6() {
			t = "AAAA"
		}
		p.Records = append(p.Records, Record{Type: t, Name: name, Value: a.String()})
	}

	dns := Check{ID: "dns", Status: CheckOK, Text: fmt.Sprintf("Every A/AAAA record of %s leads to this server. This is a precondition for a certificate, not a guarantee of one.", name)}
	if !v.OK {
		dns.Status, dns.Text = CheckFailed, strings.Join(v.Problems, "; ")
	}
	p.Checks = []Check{
		dns,
		{ID: "dns_only", Status: CheckUnchecked, Text: "The name must be DNS-only: a CDN or proxy in front (an orange cloud) breaks certificate issuance and the check from outside."},
		{ID: "ports", Status: CheckUnchecked, Text: "Port 80 (or 443) must reach this server from the internet and be free for the certificate challenge, and the chosen HTTPS port must be open in every firewall. The installer binds and tests these when the change is applied."},
		{ID: "issuance", Status: CheckUnchecked, Text: "Whether the certificate authority issues the certificate is known only after it is requested. Let's Encrypt limits repeated requests; a failure rolls the change back."},
		{ID: "reachable", Status: CheckUnchecked, Text: "That the panel is reachable at the new address over a verified certificate is confirmed after applying, and only then is the new link offered."},
	}
	return p, nil
}

// Change is one line of the plan shown before applying.
type Change struct {
	What string `json:"what"`
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// Plan is what the person confirms. PlanID ties the confirmation to exactly
// this plan; Command is the same change run by hand on the server.
type Plan struct {
	Params       Params   `json:"params"`
	PlanID       string   `json:"plan_id"`
	Command      string   `json:"command"`
	Changes      []Change `json:"changes"`
	Kept         []string `json:"kept"`
	Interruption string   `json:"interruption"`
	Rollback     string   `json:"rollback"`
	NewURL       string   `json:"new_url,omitempty"`
}

// BuildPlan describes a validated change against the current address.
func BuildPlan(p Params, currentURL string) Plan {
	plan := Plan{Params: p, PlanID: PlanID(p, currentURL), Command: Command(p)}
	port := ""
	if p.HTTPSPort != "" && p.HTTPSPort != "auto" && p.HTTPSPort != "443" {
		port = ":" + p.HTTPSPort
	}
	switch p.Action {
	case ActionDomain:
		plan.NewURL = "https://" + p.Site + port
		plan.Changes = []Change{
			{What: "Address of the panel", From: currentURL, To: plan.NewURL},
			{What: "Certificate", To: "a new certificate for " + p.Site + " is requested from Let's Encrypt"},
		}
		if p.HTTPSPort == "auto" || p.HTTPSPort == "" {
			plan.Changes = append(plan.Changes, Change{What: "HTTPS port", To: "kept, or chosen by the installer (443 first)"})
		}
	case ActionIP:
		plan.NewURL = "https://" + firstNonEmpty(p.Site, "<this server's public IP>") + port
		plan.Changes = []Change{
			{What: "Address of the panel", From: currentURL, To: plan.NewURL},
			{What: "Certificate", To: "a short-lived Let's Encrypt certificate for the address (renewed automatically)"},
		}
	case ActionTunnel:
		plan.Changes = []Change{
			{What: "Address of the panel", From: currentURL, To: "http://127.0.0.1:<port> through an SSH tunnel; the public port is closed"},
		}
	case ActionUpdate:
		plan.Changes = []Change{{What: "Application", To: "agent, web panel and helper images are updated to the version the installer finds"}}
	case ActionCheck:
		plan.Changes = []Change{{What: "Nothing is changed", To: "the installer only checks the current state"}}
	}
	plan.Kept = []string{"events and the journal", "bans and the allowlist", "login and password", "Telegram settings", "agent settings"}
	switch p.Action {
	case ActionCheck:
		plan.Interruption = "none"
	default:
		plan.Interruption = "The panel and its proxy are restarted: expect a short interruption, and the old address stops answering once the new one is up. Your session ends; sign in again at the new address."
	}
	plan.Rollback = "The configuration that works now is saved first. If the certificate, the proxy start or the page check fails, the previous configuration is restored and the reason is shown."
	return plan
}
