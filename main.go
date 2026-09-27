// longx-cert obtains TLS certificates for a Longx server through the ACME
// DNS-01 challenge with any of lego's DNS providers. Longx downloads it on
// first use and talks to it in JSON:
//
//	longx-cert --version
//	longx-cert providers            the DNS providers and the variables each reads
//	longx-cert obtain < request     one issuance; the result or the error on stdout
//
// stdout carries exactly one JSON document; lego's log goes to stderr as
// JSON lines.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime/debug"

	"github.com/go-acme/lego/v5/log"
	"github.com/mjason/longx-cert/internal/cert"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	log.SetDefault(slog.New(slog.NewJSONHandler(stderr, nil)))
	command := ""
	if len(args) > 0 {
		command = args[0]
	}
	switch command {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "longx-cert %s (lego %s)\n", cert.Version, legoVersion())
		return 0
	case "providers":
		return writeJSON(stdout, stderr, cert.Catalog(), 0)
	case "obtain":
		return obtain(stdin, stdout, stderr)
	default:
		fmt.Fprintln(stderr, "usage: longx-cert --version | providers | obtain < request.json")
		return 2
	}
}

func obtain(stdin io.Reader, stdout, stderr io.Writer) int {
	fail := func(err error) int {
		return writeJSON(stdout, stderr, map[string]any{"ok": false, "error": err.Error()}, 1)
	}
	body, err := io.ReadAll(stdin)
	if err != nil {
		return fail(fmt.Errorf("request: %w", err))
	}
	req, err := cert.ParseRequest(body)
	if err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), req.Timeout())
	defer cancel()
	res, err := cert.Obtain(ctx, req)
	if err != nil {
		return fail(err)
	}
	return writeJSON(stdout, stderr, struct {
		OK bool `json:"ok"`
		*cert.Result
	}{true, res}, 0)
}

func writeJSON(stdout, stderr io.Writer, value any, code int) int {
	if err := json.NewEncoder(stdout).Encode(value); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return code
}

func legoVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/go-acme/lego/v5" {
				return dep.Version
			}
		}
	}
	return "unknown"
}
