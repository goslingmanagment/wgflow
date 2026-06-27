package main

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// PersonGroup is one configured person and the WireGuard peers that are them.
type PersonGroup struct {
	Display string
	Devices []string
}

// AliasConfig maps WireGuard peer names into people and (optionally) overrides
// the device-kind guess. It is intentionally nil-safe: every method works on a
// nil receiver so callers never have to check whether a config was loaded.
type AliasConfig struct {
	personByDevice map[string]string
	kindByDevice   map[string]string
	people         []PersonGroup
	roster         []string
}

type clientsConfigFile struct {
	People []struct {
		Display string   `yaml:"display"`
		Devices []string `yaml:"devices"`
	} `yaml:"people"`
	DeviceKind map[string]string `yaml:"device_kind"`
}

// loadAliasConfig reads clients.yaml. A missing file is NOT an error — aliases are
// optional and callers fall back to name-prefix grouping + the suffix kind guess.
func loadAliasConfig(path string) (*AliasConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &AliasConfig{}, nil
		}
		return nil, err
	}
	var f clientsConfigFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	ac := &AliasConfig{
		personByDevice: map[string]string{},
		kindByDevice:   map[string]string{},
	}
	for _, p := range f.People {
		display := strings.TrimSpace(p.Display)
		grp := PersonGroup{Display: display}
		for _, dev := range p.Devices {
			dev = strings.TrimSpace(dev)
			if dev == "" {
				continue
			}
			if display != "" {
				ac.personByDevice[dev] = display
			}
			grp.Devices = append(grp.Devices, dev)
			ac.roster = append(ac.roster, dev)
		}
		if len(grp.Devices) > 0 {
			ac.people = append(ac.people, grp)
		}
	}
	for dev, kind := range f.DeviceKind {
		switch strings.TrimSpace(strings.ToLower(kind)) {
		case "phone", "laptop":
			ac.kindByDevice[strings.TrimSpace(dev)] = strings.ToLower(strings.TrimSpace(kind))
		}
	}
	return ac, nil
}

// Person returns the configured display name for a device, else a graceful
// fallback: the prefix before the first '-', else the whole name (so "mom" and
// odd/hyphenless names are never orphaned).
func (a *AliasConfig) Person(name string) string {
	if a != nil {
		if p, ok := a.personByDevice[name]; ok && p != "" {
			return p
		}
	}
	if i := strings.IndexByte(name, '-'); i > 0 {
		return name[:i]
	}
	return name
}

// Kind returns the configured device-kind override ("phone"/"laptop") or "".
func (a *AliasConfig) Kind(name string) string {
	if a == nil {
		return ""
	}
	return a.kindByDevice[name]
}

// Roster is every configured device name — the basis for showing silent devices
// on the board even when they had no traffic in the window.
func (a *AliasConfig) Roster() []string {
	if a == nil {
		return nil
	}
	return a.roster
}
