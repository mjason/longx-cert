package cert

import (
	"strings"
	"testing"
	"time"
)

func TestParseRequestDefaults(t *testing.T) {
	req, err := ParseRequest([]byte(`{"domains":[" LX.Example.com "],"provider":"tencentcloud","env":{"TENCENTCLOUD_SECRET_ID":"id"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if req.Directory != "https://acme-v02.api.letsencrypt.org/directory" {
		t.Errorf("directory %q, want Let's Encrypt production", req.Directory)
	}
	if got := strings.Join(req.Domains, ","); got != "lx.example.com" {
		t.Errorf("domains %q, want trimmed and lowercased", got)
	}
	if req.KeyType != "EC256" {
		t.Errorf("key type %q, want EC256", req.KeyType)
	}
	if !req.PropagationCheckEnabled() {
		t.Error("the propagation check is on unless turned off")
	}
	if req.Timeout() != 10*time.Minute {
		t.Errorf("timeout %v, want 10m", req.Timeout())
	}
}

func TestParseRequestDirectory(t *testing.T) {
	for in, want := range map[string]string{
		"letsencrypt":         "https://acme-v02.api.letsencrypt.org/directory",
		"letsencrypt-staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
		"https://ca.test/dir": "https://ca.test/dir",
	} {
		req, err := ParseRequest([]byte(`{"directory":"` + in + `","domains":["a.test"],"provider":"exec"}`))
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if req.Directory != want {
			t.Errorf("%s: directory %q, want %q", in, req.Directory, want)
		}
	}
	for _, bad := range []string{"ftp://ca.test/dir", "no-such-ca"} {
		if _, err := ParseRequest([]byte(`{"directory":"` + bad + `","domains":["a.test"],"provider":"exec"}`)); err == nil || !strings.Contains(err.Error(), "directory") {
			t.Errorf("%s: want a directory error, got %v", bad, err)
		}
	}
}

func TestParseRequestRejects(t *testing.T) {
	for name, tc := range map[string]struct{ body, field string }{
		"not json":         {`{`, "request"},
		"no domains":       {`{"provider":"exec"}`, "domains"},
		"an empty domain":  {`{"domains":["a.test",""],"provider":"exec"}`, "domains"},
		"a bad domain":     {`{"domains":["a b.test"],"provider":"exec"}`, "domains"},
		"no provider":      {`{"domains":["a.test"]}`, "provider"},
		"unknown provider": {`{"domains":["a.test"],"provider":"no-such-dns"}`, "provider"},
		"unknown key type": {`{"domains":["a.test"],"provider":"exec","key_type":"DSA"}`, "key_type"},
	} {
		_, err := ParseRequest([]byte(tc.body))
		if err == nil || !strings.Contains(err.Error(), tc.field) {
			t.Errorf("%s: want an error naming %q, got %v", name, tc.field, err)
		}
	}
}

func TestParseRequestAcceptsAWildcard(t *testing.T) {
	req, err := ParseRequest([]byte(`{"domains":["*.lx.example.com","lx.example.com"],"provider":"exec","key_type":"rsa2048","propagation_check":false,"propagation_wait_s":5,"timeout_s":30}`))
	if err != nil {
		t.Fatal(err)
	}
	if req.KeyType != "RSA2048" || req.PropagationCheckEnabled() || req.Timeout() != 30*time.Second {
		t.Errorf("parsed %+v", req)
	}
}
