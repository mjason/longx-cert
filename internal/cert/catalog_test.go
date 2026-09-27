package cert

import (
	"slices"
	"testing"
)

func TestCatalogListsTheProvidersLegoKnows(t *testing.T) {
	providers := Catalog()
	if len(providers) < 150 {
		t.Fatalf("%d providers, want lego's whole list", len(providers))
	}
	byCode := map[string]Provider{}
	for _, p := range providers {
		if p.Code == "" || p.Name == "" {
			t.Errorf("a provider without code or name: %+v", p)
		}
		byCode[p.Code] = p
	}
	for code, want := range map[string][]string{
		"tencentcloud": {"TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY"},
		"alidns":       {"ALICLOUD_ACCESS_KEY", "ALICLOUD_SECRET_KEY"},
		"cloudflare":   nil,
		"huaweicloud":  nil,
		"exec":         {"EXEC_PATH"},
		"httpreq":      {"HTTPREQ_ENDPOINT"},
		"dnsupdate":    nil,
	} {
		p, ok := byCode[code]
		if !ok {
			t.Errorf("%s is not in the catalog", code)
			continue
		}
		names := []string{}
		for _, v := range p.Credentials {
			names = append(names, v.Name)
		}
		for _, name := range want {
			if !slices.Contains(names, name) {
				t.Errorf("%s: credential %s missing from %v", code, name, names)
			}
		}
	}
	if byCode["tencentcloud"].Credentials[0].Description == "" {
		t.Error("a credential carries lego's description")
	}
	if _, ok := byCode["manual"]; ok {
		t.Error("manual waits on a terminal: not offered")
	}
	if !slices.Contains(byCode["dnsupdate"].Aliases, "rfc2136") {
		t.Errorf("dnsupdate's aliases %v, want rfc2136", byCode["dnsupdate"].Aliases)
	}
}

func TestKnown(t *testing.T) {
	if !Known("tencentcloud") || !Known("acme-dns") || !Known("rfc2136") || Known("no-such-dns") || Known("manual") {
		t.Error("Known answers from the catalog and lego's aliases")
	}
}
