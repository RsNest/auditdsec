// Command auditdsec-probe is the RemoteProbe service: a small HTTPS API that
// connects to a server's public address and port from where it runs and says
// what happened. Run it on a machine OTHER than the one being checked; a check
// made from the server itself proves nothing about the internet.
//
//	auditdsec-probe -listen :8443 -cert fullchain.pem -key privkey.pem -token-file token
//
// It is built so that it cannot be turned into a scanner or a way into a
// private network: it needs the token, refuses private, loopback, link-local
// and metadata targets, connects only to the literal address it validated,
// follows no redirects, and limits how often and how many checks run.
package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/RsNest/auditdsec/internal/netcheck"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8443", "address to serve on")
	cert := flag.String("cert", "", "TLS certificate (PEM). Without it only a loopback listener is allowed.")
	key := flag.String("key", "", "TLS key (PEM)")
	tokenFile := flag.String("token-file", "", "file holding the bearer token clients must send")
	genToken := flag.Bool("generate-token", false, "print a new random token and exit")
	perMin := flag.Int("rate", 30, "checks per minute, all callers together")
	perTarget := flag.Int("rate-per-target", 6, "checks per minute for one target address")
	active := flag.Int("max-active", 4, "checks running at once")
	allowPrivate := flag.Bool("allow-private-targets", false, "TEST ONLY: allow loopback and private targets")
	rootsFile := flag.String("roots", "", "verify the checked servers' certificates against this CA file instead of the system roots (a private or test CA)")
	flag.Parse()

	if *genToken {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(b))
		return
	}
	if *tokenFile == "" {
		log.Fatal("-token-file is required (make a token with -generate-token)")
	}
	tb, err := os.ReadFile(*tokenFile)
	if err != nil {
		log.Fatalf("cannot read the token: %v", err)
	}
	token := strings.TrimSpace(string(tb))
	if len(token) < 32 {
		log.Fatal("the token must be at least 32 characters")
	}
	if *allowPrivate {
		log.Print("WARNING: -allow-private-targets is on; this must not face the internet")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		log.Fatalf("-listen: %v", err)
	}
	if *cert == "" {
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			log.Fatal("without -cert/-key it may only listen on a loopback address: the token would cross the network in clear text")
		}
	}
	var roots *x509.CertPool
	if *rootsFile != "" {
		b, err := os.ReadFile(*rootsFile)
		if err != nil {
			log.Fatalf("-roots: %v", err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(b) {
			log.Fatalf("-roots: no certificate in %s", *rootsFile)
		}
		log.Printf("certificates are verified against %s, not the system roots", *rootsFile)
	}
	svc := &netcheck.Service{
		Checker: &netcheck.Checker{AllowPrivate: *allowPrivate, Roots: roots, Timeout: 8 * time.Second},
		Token:   token, PerMinute: *perMin, PerTarget: *perTarget, MaxActive: *active,
	}
	srv := &http.Server{Addr: *listen, Handler: svc.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 60 * time.Second}
	log.Printf("auditdsec-probe listening on %s", *listen)
	if *cert != "" {
		log.Fatal(srv.ListenAndServeTLS(*cert, *key))
	}
	log.Fatal(srv.ListenAndServe())
}
