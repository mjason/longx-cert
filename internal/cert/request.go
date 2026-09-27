// Package cert obtains a certificate from an ACME CA (Let's Encrypt by
// default) through a DNS-01 challenge, with any DNS provider lego supports:
// the server the certificate is for never has to be reachable from the
// internet, which is what a Longx on a LAN needs.
package cert

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/lego"
)

// Request is what `longx-cert obtain` reads on stdin.
type Request struct {
	// an ACME directory URL, or "letsencrypt" (the default) / "letsencrypt-staging"
	Directory string   `json:"directory"`
	Email     string   `json:"email,omitempty"`
	Domains   []string `json:"domains"`
	// EC256 (default), EC384, RSA2048, RSA3072, RSA4096
	KeyType string `json:"key_type,omitempty"`
	// a lego DNS provider code or alias (`longx-cert providers`)
	Provider string `json:"provider"`
	// the provider's variables by lego's names (credentials and options);
	// set in this process for the run only
	Env map[string]string `json:"env,omitempty"`
	// the account a previous run returned; nil registers a new one
	Account *Account `json:"account,omitempty"`
	// recursive nameservers for the propagation check (host or host:port)
	Resolvers []string `json:"resolvers,omitempty"`
	// false skips the propagation check and waits propagation_wait_s instead
	PropagationCheck *bool `json:"propagation_check,omitempty"`
	PropagationWaitS int   `json:"propagation_wait_s,omitempty"`
	// the whole run; 10 minutes when unset
	TimeoutS int `json:"timeout_s,omitempty"`
}

// Account is an ACME account: its key, where it lives, and at which CA.
type Account struct {
	Directory string `json:"directory"`
	Email     string `json:"email,omitempty"`
	Key       string `json:"key"`
	URI       string `json:"uri,omitempty"`
}

var keyTypes = []string{"EC256", "EC384", "RSA2048", "RSA3072", "RSA4096"}

// a DNS name, optionally a wildcard; IDNs arrive as punycode
var domainPattern = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ParseRequest reads and checks a request; every error names the field.
func ParseRequest(body []byte) (*Request, error) {
	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("request: not valid JSON: %w", err)
	}

	switch dir := strings.TrimSpace(req.Directory); {
	case dir == "" || dir == lego.CodeLetsEncrypt:
		req.Directory = lego.DirectoryURLLetsEncrypt
	case dir == lego.CodeLetsEncryptStaging:
		req.Directory = lego.DirectoryURLLetsEncryptStaging
	case strings.HasPrefix(dir, "https://"):
		req.Directory = dir
	default:
		return nil, fmt.Errorf("directory: %q is neither an https URL nor letsencrypt / letsencrypt-staging", dir)
	}

	if len(req.Domains) == 0 {
		return nil, fmt.Errorf("domains: at least one is needed")
	}
	for i, d := range req.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if !domainPattern.MatchString(d) {
			return nil, fmt.Errorf("domains: %q is not a DNS name", req.Domains[i])
		}
		req.Domains[i] = d
	}

	req.Provider = strings.TrimSpace(req.Provider)
	if req.Provider == "" {
		return nil, fmt.Errorf("provider: a DNS provider is needed (longx-cert providers lists them)")
	}
	if !Known(req.Provider) {
		return nil, fmt.Errorf("provider: %q is not a DNS provider lego knows", req.Provider)
	}

	if req.KeyType == "" {
		req.KeyType = "EC256"
	}
	req.KeyType = strings.ToUpper(req.KeyType)
	if !contains(keyTypes, req.KeyType) {
		return nil, fmt.Errorf("key_type: %q is not one of %s", req.KeyType, strings.Join(keyTypes, ", "))
	}

	for i, r := range req.Resolvers {
		if _, _, err := net.SplitHostPort(r); err != nil {
			req.Resolvers[i] = net.JoinHostPort(r, "53")
		}
	}
	return &req, nil
}

// PropagationCheckEnabled: lego checks that the TXT record is visible before
// asking the CA to validate, unless the request turned it off.
func (r *Request) PropagationCheckEnabled() bool {
	return r.PropagationCheck == nil || *r.PropagationCheck
}

// Timeout bounds the whole run.
func (r *Request) Timeout() time.Duration {
	if r.TimeoutS > 0 {
		return time.Duration(r.TimeoutS) * time.Second
	}
	return 10 * time.Minute
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
