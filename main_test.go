package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"--version"}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.HasPrefix(out.String(), "longx-cert ") || !strings.Contains(out.String(), "lego") {
		t.Errorf("version %q", out.String())
	}
}

func TestProvidersIsTheCatalogAsJSON(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"providers"}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	var providers []struct {
		Code        string `json:"code"`
		Credentials []struct {
			Name string `json:"name"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(out.Bytes(), &providers); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range providers {
		found = found || (p.Code == "tencentcloud" && len(p.Credentials) == 2)
	}
	if !found {
		t.Error("tencentcloud with its two credentials is listed")
	}
}

// stdout is one JSON object whatever happens; lego's log goes to stderr
func TestObtainAnswersJSONAndExitsNonZeroOnFailure(t *testing.T) {
	for name, body := range map[string]string{
		"a bad request":         `{"domains":[]}`,
		"a provider unset":      `{"directory":"https://127.0.0.1:1/dir","domains":["a.test"],"provider":"tencentcloud"}`,
		"not json at all":       `nope`,
		"no request whatsoever": ``,
	} {
		var out, errOut bytes.Buffer
		code := run([]string{"obtain"}, strings.NewReader(body), &out, &errOut)
		if code != 1 {
			t.Errorf("%s: exit %d", name, code)
		}
		var answer struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(out.Bytes(), &answer); err != nil {
			t.Errorf("%s: stdout is not one JSON object: %q", name, out.String())
			continue
		}
		if answer.OK || answer.Error == "" {
			t.Errorf("%s: answer %+v", name, answer)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"frobnicate"}, strings.NewReader(""), &out, &errOut); code != 2 {
		t.Errorf("exit %d", code)
	}
	if !strings.Contains(errOut.String(), "obtain") {
		t.Errorf("usage %q", errOut.String())
	}
}
