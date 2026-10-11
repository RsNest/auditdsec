package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/RsNest/auditdsec/internal/logging"
)

// cmdLogs prints every record of one operation from all the JSON streams in
// the log directory, oldest first. It reads files only: it needs no Docker and
// no network, and it prints what the files hold (secrets were masked when the
// records were written).
//
//	auditdsec logs --trace ID [--dir DIR]
func cmdLogs(args []string) error {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	trace := fs.String("trace", "", "the trace ID of the operation (16 to 32 hex characters)")
	dir := fs.String("dir", envOr("AUDITDSEC_LOG_DIR", "/var/log/auditseclogs"), "the log directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *trace == "" {
		return fmt.Errorf("logs: give --trace ID (the ID is in the installer's result, in a failure message and in the panel)")
	}
	lines, truncated, err := logging.FindTrace(*dir, *trace)
	if err != nil {
		return fmt.Errorf("logs: %w", err)
	}
	for _, l := range lines {
		fmt.Println(l)
	}
	if truncated {
		fmt.Fprintf(os.Stderr, "auditdsec: the answer was cut at %d records or %d MiB; narrow it by reading the files directly\n",
			logging.TraceMaxLines, logging.TraceMaxBytes>>20)
	}
	if len(lines) == 0 {
		fmt.Fprintf(os.Stderr, "auditdsec: no records with trace_id %s in %s\n", *trace, *dir)
		return exitCode(1)
	}
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
