// Package inventory provides device inventory management (shared with netmodel)
package inventory

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Inventory holds device groups and defaults
type Inventory struct {
	Groups   map[string][]string `yaml:"groups"`
	Hosts    map[string]Host     `yaml:"hosts,omitempty"`
	Defaults Defaults            `yaml:"defaults,omitempty"`
}

// Host defines per-host settings
type Host struct {
	Address  string `yaml:"address,omitempty"`
	Port     int    `yaml:"port,omitempty"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	Insecure *bool  `yaml:"insecure,omitempty"`
}

// Defaults for all devices in inventory
type Defaults struct {
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	Insecure bool   `yaml:"insecure,omitempty"`
	Port     int    `yaml:"port,omitempty"`
}

// Load loads inventory from a file
func Load(path string) (*Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read inventory: %w", err)
	}

	var inv Inventory
	if err := yaml.Unmarshal(data, &inv); err != nil {
		return nil, err
	}

	inv.expandReferences()
	return &inv, nil
}

// expandReferences expands @group references in groups
func (inv *Inventory) expandReferences() {
	maxDepth := 10
	for i := 0; i < maxDepth; i++ {
		changed := false
		for name, members := range inv.Groups {
			var expanded []string
			for _, member := range members {
				if strings.HasPrefix(member, "@") {
					refName := strings.TrimPrefix(member, "@")
					if refMembers, ok := inv.Groups[refName]; ok {
						expanded = append(expanded, refMembers...)
						changed = true
						continue
					}
				}
				expanded = append(expanded, member)
			}
			inv.Groups[name] = expanded
		}
		if !changed {
			break
		}
	}
}

// GetGroup returns all hosts in a group
func (inv *Inventory) GetGroup(name string) ([]string, bool) {
	hosts, ok := inv.Groups[name]
	return hosts, ok
}

// ResolveHost returns the full target address for a host (address:port)
func (inv *Inventory) ResolveHost(name string) string {
	address := name
	port := inv.Defaults.Port

	if host, ok := inv.Hosts[name]; ok {
		if host.Address != "" {
			address = host.Address
		}
		if host.Port != 0 {
			port = host.Port
		}
	}

	// Add port if specified and not already in address
	if port != 0 && !strings.Contains(address, ":") {
		return fmt.Sprintf("%s:%d", address, port)
	}

	return address
}

// GetHostCredentials returns credentials for a host
func (inv *Inventory) GetHostCredentials(name string) (username, password string, insecure bool) {
	username = inv.Defaults.Username
	password = inv.Defaults.Password
	insecure = inv.Defaults.Insecure

	if host, ok := inv.Hosts[name]; ok {
		if host.Username != "" {
			username = host.Username
		}
		if host.Password != "" {
			password = host.Password
		}
		if host.Insecure != nil {
			insecure = *host.Insecure
		}
	}

	return
}

// ListGroups returns all group names
func (inv *Inventory) ListGroups() []string {
	names := make([]string, 0, len(inv.Groups))
	for name := range inv.Groups {
		names = append(names, name)
	}
	return names
}
