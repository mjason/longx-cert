package cert

import (
	"context"
	"crypto"
	"fmt"
	"os"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/providers/dns"
	"github.com/go-acme/lego/v5/registration"
)

// Version is this build's, set with -ldflags "-X …/internal/cert.Version=v0.1.0".
var Version = "dev"

// Result is a certificate: the leaf followed by its chain, its key, and the
// account that obtained it (to be handed back for the renewal).
type Result struct {
	Certificate string    `json:"certificate"`
	PrivateKey  string    `json:"private_key"`
	Issuer      string    `json:"issuer"`
	Domains     []string  `json:"domains"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Serial      string    `json:"serial"`
	CertURL     string    `json:"cert_url"`
	Account     Account   `json:"account"`
}

type user struct {
	email string
	key   crypto.Signer
	reg   *acme.ExtendedAccount
}

func (u *user) GetEmail() string                       { return u.email }
func (u *user) GetRegistration() *acme.ExtendedAccount { return u.reg }
func (u *user) GetPrivateKey() crypto.Signer           { return u.key }

// Obtain runs one issuance: the provider is configured from the request's
// variables first (a missing credential fails here, before the CA is
// asked), the account is the request's when it was made at this CA, else a
// new one, and the certificate comes back with its chain.
func Obtain(ctx context.Context, req *Request) (*Result, error) {
	restore := setEnv(req.Env)
	defer restore()

	provider, err := dns.NewDNSChallengeProviderByName(req.Provider)
	if err != nil {
		return nil, fmt.Errorf("provider %s: %w", req.Provider, err)
	}

	u, fresh, err := accountUser(req)
	if err != nil {
		return nil, err
	}
	config := lego.NewConfig(u)
	config.CADirURL = req.Directory
	config.UserAgent = "longx-cert/" + Version
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("the CA at %s: %w", req.Directory, err)
	}

	if len(req.Resolvers) > 0 {
		options := dns01.NewOptions()
		options.RecursiveNameservers = req.Resolvers
		options.Timeout = 10 * time.Second
		dns01.SetDefaultClient(dns01.NewClient(options))
	}
	var options []dns01.ChallengeOption
	if !req.PropagationCheckEnabled() {
		options = append(options, dns01.PropagationWait(time.Duration(req.PropagationWaitS)*time.Second, true))
	}
	if err := client.Challenge.SetDNS01Provider(provider, options...); err != nil {
		return nil, err
	}

	if fresh {
		reg, err := client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("registering an account at %s: %w", req.Directory, err)
		}
		u.reg = reg
	}

	res, err := client.Certificate.Obtain(ctx, certificate.ObtainRequest{
		Domains: req.Domains,
		KeyType: certcrypto.KeyType(req.KeyType),
		Bundle:  true,
	})
	if err != nil {
		return nil, err
	}
	leaf, err := certcrypto.ParsePEMCertificate(res.Certificate)
	if err != nil {
		return nil, fmt.Errorf("the CA's certificate: %w", err)
	}

	return &Result{
		Certificate: string(res.Certificate),
		PrivateKey:  string(res.PrivateKey),
		Issuer:      string(res.IssuerCertificate),
		Domains:     certcrypto.ExtractDomains(leaf),
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
		Serial:      leaf.SerialNumber.Text(16),
		CertURL:     res.CertURL,
		Account: Account{
			Directory: req.Directory,
			Email:     req.Email,
			Key:       string(certcrypto.PEMEncode(u.key)),
			URI:       u.reg.Location,
		},
	}, nil
}

// the request's account when it belongs to this CA; a new key otherwise
func accountUser(req *Request) (*user, bool, error) {
	if a := req.Account; a != nil && a.Key != "" && a.Directory == req.Directory {
		key, err := certcrypto.ParsePEMPrivateKey([]byte(a.Key))
		if err != nil {
			return nil, false, fmt.Errorf("account: the key does not parse: %w", err)
		}
		u := &user{email: req.Email, key: key}
		if a.URI == "" {
			return u, true, nil
		}
		u.reg = &acme.ExtendedAccount{Location: a.URI}
		return u, false, nil
	}
	key, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
	if err != nil {
		return nil, false, err
	}
	return &user{email: req.Email, key: key}, true, nil
}

// sets the variables and returns what puts the environment back as it was
func setEnv(env map[string]string) func() {
	type previous struct {
		value string
		set   bool
	}
	saved := map[string]previous{}
	for k, v := range env {
		old, ok := os.LookupEnv(k)
		saved[k] = previous{old, ok}
		_ = os.Setenv(k, v)
	}
	return func() {
		for k, p := range saved {
			if p.set {
				_ = os.Setenv(k, p.value)
			} else {
				_ = os.Unsetenv(k)
			}
		}
	}
}
