package cert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pebble and its DNS test server play Let's Encrypt here:
//
//	go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
//	go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest
//
// The tests that need them are skipped when they are not installed.

func TestObtainAgainstPebble(t *testing.T) {
	ca := startPebble(t)
	hook := dnsHook(t, ca.management)

	req, err := ParseRequest([]byte(fmt.Sprintf(`{
		"directory": %q,
		"domains": ["longx.example.com"],
		"provider": "httpreq",
		"env": {"HTTPREQ_ENDPOINT": %q, "LEGO_CA_CERTIFICATES": %q},
		"resolvers": [%q],
		"propagation_check": false,
		"timeout_s": 120
	}`, ca.directory, hook.URL, ca.caFile, ca.dns)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	first, err := Obtain(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	leaf := parseLeaf(t, first.Certificate)
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "longx.example.com" {
		t.Errorf("names %v", leaf.DNSNames)
	}
	if strings.Join(first.Domains, ",") != "longx.example.com" || !first.NotAfter.Equal(leaf.NotAfter) || first.Serial == "" {
		t.Errorf("result %+v", first)
	}
	if !first.NotAfter.After(time.Now().Add(24 * time.Hour)) {
		t.Errorf("not after %v", first.NotAfter)
	}
	// the chain comes with the leaf, and the key is the leaf's
	if strings.Count(first.Certificate, "BEGIN CERTIFICATE") < 2 || first.Issuer == "" {
		t.Error("the certificate is the leaf followed by its chain")
	}
	if _, err := tls.X509KeyPair([]byte(first.Certificate), []byte(first.PrivateKey)); err != nil {
		t.Errorf("the key does not match the certificate: %v", err)
	}
	if first.Account.Key == "" || first.Account.URI == "" || first.Account.Directory != ca.directory {
		t.Errorf("account %+v", first.Account)
	}
	// the credentials were the process's for the run only
	if v, ok := os.LookupEnv("HTTPREQ_ENDPOINT"); ok {
		t.Errorf("HTTPREQ_ENDPOINT left set: %q", v)
	}

	// a renewal signs in with the account it was given
	req.Account = &first.Account
	second, err := Obtain(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if second.Account.URI != first.Account.URI {
		t.Errorf("a new account %s, want %s", second.Account.URI, first.Account.URI)
	}
	if second.Serial == first.Serial {
		t.Error("a renewal is a new certificate")
	}

	// an account made with another CA is not presented to this one
	other := first.Account
	other.Directory = "https://elsewhere.test/directory"
	req.Account = &other
	third, err := Obtain(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if third.Account.URI == first.Account.URI || third.Account.Directory != ca.directory {
		t.Errorf("account %+v, want a new one at %s", third.Account, ca.directory)
	}
}

func TestObtainFailsOnTheProvidersConfigurationBeforeAnyRequest(t *testing.T) {
	req, err := ParseRequest([]byte(`{"directory":"https://127.0.0.1:1/dir","domains":["a.test"],"provider":"tencentcloud"}`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Obtain(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "TENCENTCLOUD_SECRET_ID") {
		t.Fatalf("want lego's missing-variable error, got %v", err)
	}
}

// ---- pebble ----------------------------------------------------------------

type testCA struct {
	directory  string // pebble's ACME directory
	caFile     string // the certificate pebble's HTTPS listener presents
	management string // challtestsrv's management API
	dns        string // challtestsrv's DNS server, host:port
}

func startPebble(t *testing.T) testCA {
	t.Helper()
	pebble := findBinary(t, "pebble")
	chall := findBinary(t, "pebble-challtestsrv")
	dir := t.TempDir()

	dnsAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	mgmtAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	start(t, nil, chall, "-dnsserver", dnsAddr, "-management", mgmtAddr,
		"-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", "")
	waitTCP(t, mgmtAddr)

	certFile, keyFile := selfSigned(t, dir)
	acmeAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	config := map[string]any{"pebble": map[string]any{
		"listenAddress":                  acmeAddr,
		"managementListenAddress":        fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		"certificate":                    certFile,
		"privateKey":                     keyFile,
		"httpPort":                       freePort(t),
		"tlsPort":                        freePort(t),
		"ocspResponderURL":               "",
		"externalAccountBindingRequired": false,
	}}
	configFile := filepath.Join(dir, "pebble.json")
	data, _ := json.Marshal(config)
	if err := os.WriteFile(configFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// no random nonce rejections, no sleeps before validation
	env := []string{"PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0"}
	start(t, env, pebble, "-config", configFile, "-dnsserver", dnsAddr)
	waitTCP(t, acmeAddr)

	return testCA{
		directory:  "https://" + acmeAddr + "/dir",
		caFile:     certFile,
		management: "http://" + mgmtAddr,
		dns:        dnsAddr,
	}
}

// the DNS provider handed to lego: httpreq, whose requests become TXT
// records in challtestsrv — the DNS server pebble validates against
func dnsHook(t *testing.T, management string) *httptest.Server {
	t.Helper()
	post := func(path string, body map[string]string) error {
		data, _ := json.Marshal(body)
		resp, err := http.Post(management+path, "application/json", bytes.NewReader(data))
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s: %s", path, resp.Status)
		}
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/present", func(w http.ResponseWriter, r *http.Request) {
		var msg struct{ FQDN, Value string }
		_ = json.NewDecoder(r.Body).Decode(&msg)
		if err := post("/set-txt", map[string]string{"host": msg.FQDN, "value": msg.Value}); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
		}
	})
	mux.HandleFunc("/cleanup", func(w http.ResponseWriter, r *http.Request) {
		var msg struct{ FQDN string }
		_ = json.NewDecoder(r.Body).Decode(&msg)
		if err := post("/clear-txt", map[string]string{"host": msg.FQDN}); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func findBinary(t *testing.T, name string) string {
	t.Helper()
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		home, _ := os.UserHomeDir()
		gopath = filepath.Join(home, "go")
	}
	path := filepath.Join(gopath, "bin", name)
	if _, err := os.Stat(path); err != nil {
		t.Skipf("%s is not installed (go install github.com/letsencrypt/pebble/v2/cmd/%s@latest)", name, name)
	}
	return path
}

func start(t *testing.T, env []string, bin string, args ...string) {
	t.Helper()
	var out bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("%s:\n%s", filepath.Base(bin), out.String())
		}
	})
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s never listened", addr)
}

// a certificate for pebble's own HTTPS listener, trusted by lego through LEGO_CA_CERTIFICATES
func selfSigned(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pebble test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	return certFile, keyFile
}

func parseLeaf(t *testing.T, bundle string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(bundle))
	if block == nil {
		t.Fatalf("no PEM in %q", bundle)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
