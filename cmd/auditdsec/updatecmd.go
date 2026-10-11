package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/RsNest/auditdsec/internal/sanitize"
	"github.com/RsNest/auditdsec/internal/update"
)

// cmdUpdateInfo is what the installer asks before an update: it fetches the
// channel's document, verifies it exactly as the panel does (one
// implementation), and prints KEY=VALUE lines. Notes are printed as
// "NOTE|<text>" lines in the installer's language. It writes nothing.
//
// Exit status: 0 answered, 2 the source cannot be reached, 3 the document is
// invalid or not signed correctly.
func cmdUpdateInfo(args []string) error {
	fs := flag.NewFlagSet("update-info", flag.ContinueOnError)
	channel := fs.String("channel", os.Getenv("AUDITDSEC_UPDATE_CHANNEL"), "stable, main or empty for the default of this build")
	base := fs.String("url", os.Getenv("AUDITDSEC_UPDATE_URL"), "where the metadata is published (default: the project's)")
	lang := fs.String("lang", "en", "language of the notes: ru or en")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := update.EmbeddedKey()
	if err != nil {
		return err
	}
	ch := *channel
	if ch == "auto" {
		ch = ""
	}
	c, err := update.New(update.Options{
		Installed: update.Installed{Version: version, Commit: commit, Date: date},
		Channel:   ch, Arch: runtime.GOARCH, Base: *base, PublicKey: key,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	res, err := c.Fetch(ctx)
	if err != nil {
		var code = 2
		if errors.Is(err, update.ErrSignature) || errors.Is(err, update.ErrInvalid) {
			code = 3
		}
		fmt.Fprintln(os.Stderr, "update-info:", err)
		return exitCode(code)
	}
	line := func(k, v string) { fmt.Printf("%s=%s\n", k, oneLine(v)) }
	line("CHANNEL", c.View().Channel)
	line("INSTALLED_COMMIT", commit)
	line("INSTALLED_VERSION", version)
	line("ARCH", runtime.GOARCH)
	line("STATE", res.State)
	line("LATEST_VERSION", res.Latest.Version)
	line("LATEST_COMMIT", res.Latest.Commit)
	line("LATEST_PUBLISHED", res.Latest.Published)
	names := make([]string, 0, len(res.Latest.Images))
	for n := range res.Latest.Images {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		img := res.Latest.Images[n]
		key := strings.ToUpper(strings.ReplaceAll(n, "-", "_"))
		line("IMAGE_"+key, img.Ref)
		line("DIGEST_"+key, img.Digest)
	}
	line("REQUIRES_INSTALLER_UPDATE", map[bool]string{true: "yes", false: "no"}[res.Requires.InstallerUpdate])
	line("REQUIRES_MIGRATION", res.Requires.Migration)
	line("BREAKING_COUNT", fmt.Sprint(len(res.Breaking)))
	line("TRUNCATED", map[bool]string{true: "yes", false: "no"}[res.Truncated])
	note := func(s string) { fmt.Printf("NOTE|%s\n", oneLine(sanitize.Text(s))) }
	for _, e := range res.Entries {
		note(e.Title.Lang(*lang))
		for _, group := range [][]string{e.Added.Lang(*lang), e.Fixed.Lang(*lang), e.Changed.Lang(*lang), e.Actions.Lang(*lang)} {
			for _, s := range group {
				note("  - " + s)
			}
		}
	}
	for _, b := range res.Breaking {
		fmt.Printf("BREAKING|%s\n", oneLine(sanitize.Text(b.Lang(*lang))))
	}
	return nil
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "\x00", "")), " ")
}

// cmdUpdateValidate checks a metadata file (CI runs it on what it is about to
// publish): the same parser and, when a key is given, the same signature check
// as an installed agent.
func cmdUpdateValidate(args []string) error {
	fs := flag.NewFlagSet("update-validate", flag.ContinueOnError)
	sig := fs.String("sig", "", "detached signature file")
	key := fs.String("key", "", "base64 public key (default: the key built into this binary)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: auditdsec update-validate [-sig FILE] [-key BASE64] FILE")
	}
	doc, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	md, err := update.Parse(doc)
	if err != nil {
		return err
	}
	pub, err := update.EmbeddedKey()
	if err != nil {
		return err
	}
	if *key != "" {
		if pub, err = update.ParsePublicKey(*key); err != nil {
			return err
		}
	}
	if pub != nil {
		raw, rerr := os.ReadFile(*sig)
		if *sig == "" || rerr != nil {
			return update.ErrSignature
		}
		if err := update.Verify(doc, raw, pub); err != nil {
			return err
		}
	}
	l := md.Latest()
	fmt.Printf("valid: channel %s, build %d (%s, commit %s), %d builds, images: %d, signature: %t\n",
		md.Channel, l.Seq, l.Version, l.Commit[:12], len(md.Builds), len(l.Images), pub != nil)
	return nil
}
