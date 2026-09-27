// Command gen writes internal/cert/providers.json: every DNS provider lego
// ships, read from the descriptor each one carries in lego's module
// (providers/dns/<code>/<code>.toml) — its code, name, site, the other
// names lego accepts for it, and the environment variables it reads
// (credentials first, then the optional ones). Run through
// `go generate ./...`; CI fails when the committed file is stale.
//
// The descriptors use a small, regular part of TOML (quoted values, two
// tables, triple-quoted blocks), read here line by line so the build needs
// no TOML dependency.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type variable struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type provider struct {
	Code        string     `json:"code"`
	Name        string     `json:"name"`
	URL         string     `json:"url,omitempty"`
	Aliases     []string   `json:"aliases"`
	Credentials []variable `json:"credentials"`
	Additional  []variable `json:"additional"`
}

// providers that cannot run unattended
var skipped = map[string]bool{"manual": true}

const block = "'''"

// | `EXEC_PATH` | The path of the the external program. |
var tableRow = regexp.MustCompile("^\\|\\s*`([A-Z0-9_]+)`\\s*\\|\\s*(.*?)\\s*\\|$")

// one `case "a", "b":` of lego's generated provider switch
var caseLine = regexp.MustCompile(`^\s*case\s+(".*"):\s*$`)

func main() {
	out := flag.String("out", "providers.json", "the file to write")
	flag.Parse()

	dir, err := legoDir()
	if err != nil {
		fail(err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "providers", "dns", "*", "*.toml"))
	if err != nil {
		fail(err)
	}
	aliases, err := parseAliases(filepath.Join(dir, "providers", "dns", "zz_gen_dns_providers.go"))
	if err != nil {
		fail(err)
	}
	providers := []provider{}
	for _, file := range files {
		p, err := parse(file)
		if err != nil {
			fail(fmt.Errorf("%s: %w", file, err))
		}
		if skipped[p.Code] {
			continue
		}
		p.Aliases = aliases[p.Code]
		if p.Aliases == nil {
			p.Aliases = []string{}
		}
		providers = append(providers, p)
	}
	if len(providers) == 0 {
		fail(fmt.Errorf("no provider descriptors under %s", dir))
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].Code < providers[j].Code })

	data, err := json.MarshalIndent(providers, "", "  ")
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile(*out, append(data, '\n'), 0o644); err != nil {
		fail(err)
	}
}

// the lego module this build uses, as `go list` resolves it from go.mod
func legoDir() (string, error) {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/go-acme/lego/v5")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go list: %w", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		return "", fmt.Errorf("lego is not downloaded: run go mod download")
	}
	return dir, nil
}

func parse(file string) (provider, error) {
	f, err := os.Open(file)
	if err != nil {
		return provider{}, err
	}
	defer f.Close()

	p := provider{Credentials: []variable{}, Additional: []variable{}}
	section := ""
	inBlock := false
	// a provider that documents its variables only in markdown tables inside
	// its `Additional` block (exec): the rows under "## Base Configuration"
	// are its credentials, the rest optional
	blockKey, heading := "", ""
	seen := map[string]bool{}
	add := func(credential bool, v variable) {
		if seen[v.Name] {
			return
		}
		seen[v.Name] = true
		if credential {
			p.Credentials = append(p.Credentials, v)
		} else {
			p.Additional = append(p.Additional, v)
		}
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if inBlock {
			if strings.Contains(line, block) {
				inBlock = false
				continue
			}
			if blockKey != "Additional" {
				continue
			}
			if strings.HasPrefix(line, "## ") {
				heading = line
				continue
			}
			if m := tableRow.FindStringSubmatch(line); m != nil {
				add(strings.Contains(heading, "Base") || strings.Contains(heading, "Credentials"), variable{m[1], m[2]})
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.Trim(line, "[] ")
			continue
		}
		key, raw, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		raw = strings.TrimSpace(raw)
		if strings.HasPrefix(raw, block) {
			// a block that also ends on this line is one line long
			inBlock = strings.Count(raw, block) == 1
			blockKey, heading = key, ""
			continue
		}
		value, err := unquote(raw)
		if err != nil {
			continue
		}
		switch section {
		case "":
			switch key {
			case "Code":
				p.Code = value
			case "Name":
				p.Name = value
			case "URL":
				p.URL = value
			}
		case "Configuration.Credentials":
			add(true, variable{key, value})
		case "Configuration.Additional":
			add(false, variable{key, value})
		}
	}
	if err := scanner.Err(); err != nil {
		return provider{}, err
	}
	if p.Code == "" || p.Name == "" {
		return provider{}, fmt.Errorf("no Code or Name")
	}
	return p, nil
}

// every name lego's switch accepts beside a provider's own code, by code
func parseAliases(file string) (map[string][]string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, line := range strings.Split(string(data), "\n") {
		m := caseLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		names := []string{}
		for _, q := range strings.Split(m[1], ",") {
			name, err := strconv.Unquote(strings.TrimSpace(q))
			if err != nil {
				return nil, fmt.Errorf("%s: %q: %w", file, line, err)
			}
			names = append(names, name)
		}
		if len(names) > 1 {
			// the first is the code (the provider's directory), the rest aliases
			out[names[0]] = names[1:]
		}
	}
	return out, nil
}

func unquote(raw string) (string, error) {
	if strings.HasPrefix(raw, "'") && strings.HasSuffix(raw, "'") && len(raw) >= 2 {
		return raw[1 : len(raw)-1], nil
	}
	return strconv.Unquote(raw)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "gen:", err)
	os.Exit(1)
}
