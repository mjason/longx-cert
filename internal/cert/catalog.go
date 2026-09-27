package cert

import (
	_ "embed"
	"encoding/json"
	"sync"
)

//go:generate go run ../gen -out providers.json

// Variable is an environment variable a provider reads, with lego's description.
type Variable struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Provider is one of lego's DNS providers as its descriptor documents it.
type Provider struct {
	Code        string     `json:"code"`
	Name        string     `json:"name"`
	URL         string     `json:"url,omitempty"`
	Aliases     []string   `json:"aliases"`
	Credentials []Variable `json:"credentials"`
	Additional  []Variable `json:"additional"`
}

//go:embed providers.json
var providersJSON []byte

var catalog = sync.OnceValue(func() []Provider {
	var providers []Provider
	if err := json.Unmarshal(providersJSON, &providers); err != nil {
		panic("providers.json: " + err.Error())
	}
	return providers
})

var known = sync.OnceValue(func() map[string]bool {
	names := map[string]bool{}
	for _, p := range catalog() {
		names[p.Code] = true
		for _, a := range p.Aliases {
			names[a] = true
		}
	}
	return names
})

// Catalog is every DNS provider this build can use, by code.
func Catalog() []Provider { return catalog() }

// Known says whether a code or alias names a provider of the catalog.
func Known(name string) bool { return known()[name] }
