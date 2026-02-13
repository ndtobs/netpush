// Package applier converts netmodel YAML to gNMI Set operations
package applier

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ndtobs/netpush/internal/gnmi"
	"github.com/ndtobs/netpush/internal/transform"
	"gopkg.in/yaml.v3"
)

// Applier pushes config to devices via gNMI
type Applier struct {
	client *gnmi.Client
	dryRun bool
}

// Config for applier
type Config struct {
	Target   string
	Username string
	Password string
	Insecure bool
	DryRun   bool
}

// New creates a new applier
func New(cfg Config) (*Applier, error) {
	client, err := gnmi.NewClient(gnmi.Config{
		Address:  cfg.Target,
		Username: cfg.Username,
		Password: cfg.Password,
		Insecure: cfg.Insecure,
	})
	if err != nil {
		return nil, err
	}

	return &Applier{
		client: client,
		dryRun: cfg.DryRun,
	}, nil
}

// Close closes the connection
func (a *Applier) Close() error {
	return a.client.Close()
}

// Apply merges config (gNMI Update - additive)
func (a *Applier) Apply(ctx context.Context, data map[string]interface{}) error {
	updates := a.buildUpdates(data)

	if len(updates) == 0 {
		fmt.Println("No changes to apply")
		return nil
	}

	resp, err := a.client.Set(ctx, updates)
	if err != nil {
		return fmt.Errorf("set: %w", err)
	}
	fmt.Printf("Applied %d updates (timestamp: %d)\n", len(updates), resp.Timestamp)
	return nil
}

// Diff shows what apply would change
func (a *Applier) Diff(ctx context.Context, data map[string]interface{}) error {
	updates := a.buildUpdates(data)

	if len(updates) == 0 {
		fmt.Println("No config to apply")
		return nil
	}

	hasChanges := false
	for _, u := range updates {
		current, err := a.client.GetJSON(ctx, u.Path)
		if err != nil || current == nil {
			// Path doesn't exist - would add everything
			fmt.Printf("+ %s %s\n", u.Path, summarizeValue(u.Value))
			hasChanges = true
			continue
		}

		// For interfaces, compare at interface level
		if strings.HasSuffix(u.Path, "/interfaces") {
			diffs := diffInterfaces(current, toMap(u.Value))
			if len(diffs) > 0 {
				for _, d := range diffs {
					fmt.Println(d)
				}
				hasChanges = true
			}
			continue
		}

		// For BGP, compare key elements
		if strings.Contains(u.Path, "/bgp") {
			diffs := diffBGP(current, toMap(u.Value))
			if len(diffs) > 0 {
				for _, d := range diffs {
					fmt.Println(d)
				}
				hasChanges = true
			}
			continue
		}

		// For system paths, compare key fields
		if strings.HasPrefix(u.Path, "/system") {
			diffs := diffSystem(u.Path, current, toMap(u.Value))
			if len(diffs) > 0 {
				for _, d := range diffs {
					fmt.Println(d)
				}
				hasChanges = true
			}
			continue
		}

		// For routing-policy, compare key elements
		if strings.Contains(u.Path, "/routing-policy") {
			diffs := diffRoutingPolicy(current, toMap(u.Value))
			if len(diffs) > 0 {
				for _, d := range diffs {
					fmt.Println(d)
				}
				hasChanges = true
			}
			continue
		}

		// Generic: path exists, assume in sync (can't easily compare)
		// Only flag if path is new
	}

	if !hasChanges {
		fmt.Println("✓ Already in sync")
	}

	return nil
}

// diffInterfaces compares interfaces at a meaningful level
func diffInterfaces(current, desired map[string]interface{}) []string {
	var diffs []string

	// Get current interfaces by name
	currentIfaces := getListByName(current, "interface", "name")
	desiredIfaces := getListByName(desired, "interface", "name")

	for name, dIface := range desiredIfaces {
		cIface, exists := currentIfaces[name]
		if !exists {
			diffs = append(diffs, fmt.Sprintf("+ interface %s (new)", name))
			continue
		}

		// Compare key fields
		var ifaceDiffs []string

		// Description
		dDesc := getNestedString(dIface, "config", "description")
		cDesc := getNestedString(cIface, "config", "description")
		if dDesc != "" && dDesc != cDesc {
			ifaceDiffs = append(ifaceDiffs, fmt.Sprintf("description: %q → %q", cDesc, dDesc))
		}

		// MTU
		dMTU := getNestedValue(dIface, "config", "mtu")
		cMTU := getNestedValue(cIface, "config", "mtu")
		if dMTU != nil && fmt.Sprintf("%v", dMTU) != fmt.Sprintf("%v", cMTU) {
			ifaceDiffs = append(ifaceDiffs, fmt.Sprintf("mtu: %v → %v", cMTU, dMTU))
		}

		// IP addresses (simplified - just check if primary matches)
		dIP := getInterfaceIP(dIface)
		cIP := getInterfaceIP(cIface)
		if dIP != "" && dIP != cIP {
			ifaceDiffs = append(ifaceDiffs, fmt.Sprintf("ip: %s → %s", cIP, dIP))
		}

		if len(ifaceDiffs) > 0 {
			diffs = append(diffs, fmt.Sprintf("~ interface %s:", name))
			for _, d := range ifaceDiffs {
				diffs = append(diffs, fmt.Sprintf("    %s", d))
			}
		}
	}

	// Check for interfaces on device but not in model
	for name := range currentIfaces {
		if _, exists := desiredIfaces[name]; !exists {
			// Skip known auto-created/internal interfaces
			if shouldIgnoreInterface(name) {
				continue
			}
			diffs = append(diffs, fmt.Sprintf("- interface %s (not in model)", name))
		}
	}

	return diffs
}

// shouldIgnoreInterface returns true for auto-created/internal interfaces
func shouldIgnoreInterface(name string) bool {
	// Management interfaces
	if strings.HasPrefix(name, "Management") {
		return true
	}
	// Arista internal VLANs (4094-4097 used for MLAG, VXLAN, etc.)
	for _, internal := range []string{"Vlan4094", "Vlan4095", "Vlan4096", "Vlan4097"} {
		if name == internal {
			return true
		}
	}
	return false
}

// diffBGP compares BGP config at a meaningful level
func diffBGP(current, desired map[string]interface{}) []string {
	var diffs []string

	// Compare global
	cGlobal := getNestedMapAny(current, "global", "config")
	dGlobal := getNestedMapAny(desired, "global", "config")
	if dGlobal != nil {
		if dAS := dGlobal["as"]; dAS != nil {
			cAS := cGlobal["as"]
			if fmt.Sprintf("%v", dAS) != fmt.Sprintf("%v", cAS) {
				diffs = append(diffs, fmt.Sprintf("~ bgp global: AS %v → %v", cAS, dAS))
			}
		}
		if dRID := dGlobal["router-id"]; dRID != nil {
			cRID := cGlobal["router-id"]
			if dRID != cRID {
				diffs = append(diffs, fmt.Sprintf("~ bgp global: router-id %v → %v", cRID, dRID))
			}
		}
	}

	// Compare neighbors
	cNeighbors := getBGPNeighbors(current)
	dNeighbors := getBGPNeighbors(desired)
	for addr, dNbr := range dNeighbors {
		cNbr, exists := cNeighbors[addr]
		if !exists {
			diffs = append(diffs, fmt.Sprintf("+ neighbor %s", addr))
			continue
		}

		// Check peer-group
		dPG := getNestedString(dNbr, "config", "peer-group")
		cPG := getNestedString(cNbr, "config", "peer-group")
		if dPG != "" && dPG != cPG {
			diffs = append(diffs, fmt.Sprintf("~ neighbor %s: peer-group %q → %q", addr, cPG, dPG))
		}
	}

	// Check for neighbors on device but not in model
	for addr := range cNeighbors {
		if _, exists := dNeighbors[addr]; !exists {
			diffs = append(diffs, fmt.Sprintf("- neighbor %s (not in model)", addr))
		}
	}

	// Compare peer-groups
	cPGs := getBGPPeerGroups(current)
	dPGs := getBGPPeerGroups(desired)
	for name, dPG := range dPGs {
		_, exists := cPGs[name]
		if !exists {
			diffs = append(diffs, fmt.Sprintf("+ peer-group %s", name))
		}
		_ = dPG
	}

	// Check for peer-groups on device but not in model
	for name := range cPGs {
		if _, exists := dPGs[name]; !exists {
			diffs = append(diffs, fmt.Sprintf("- peer-group %s (not in model)", name))
		}
	}

	return diffs
}

func getListByName(m map[string]interface{}, listKey, nameKey string) map[string]map[string]interface{} {
	result := make(map[string]map[string]interface{})
	list := getSliceAnyKey(m, listKey)
	for _, item := range list {
		name := getStringAnyKey(item, nameKey)
		if name != "" {
			result[name] = item
		}
	}
	return result
}

// getStringAnyKey gets a string value trying various key formats
func getStringAnyKey(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	altKey := strings.ReplaceAll(key, "-", "_")
	if v, ok := m[altKey].(string); ok {
		return v
	}
	altKey = strings.ReplaceAll(key, "_", "-")
	if v, ok := m[altKey].(string); ok {
		return v
	}
	return ""
}

// getSliceAnyKey gets a slice from map, trying various key formats
func getSliceAnyKey(m map[string]interface{}, key string) []map[string]interface{} {
	if m == nil {
		return nil
	}
	// Try exact key first
	if v := m[key]; v != nil {
		return toSlice(v)
	}
	// Try with underscores converted to dashes and vice versa
	altKey := strings.ReplaceAll(key, "-", "_")
	if v := m[altKey]; v != nil {
		return toSlice(v)
	}
	altKey = strings.ReplaceAll(key, "_", "-")
	if v := m[altKey]; v != nil {
		return toSlice(v)
	}
	// Try with common prefixes
	for k, v := range m {
		if strings.HasSuffix(k, ":"+key) {
			return toSlice(v)
		}
	}
	return nil
}

func getSlice(m map[string]interface{}, key string) []map[string]interface{} {
	if m == nil {
		return nil
	}
	v := m[key]
	return toSlice(v)
}

func getNestedMap(m map[string]interface{}, keys ...string) map[string]interface{} {
	current := m
	for _, k := range keys {
		if current == nil {
			return nil
		}
		next, ok := current[k].(map[string]interface{})
		if !ok {
			return nil
		}
		current = next
	}
	return current
}

func getNestedString(m map[string]interface{}, keys ...string) string {
	current := m
	for i, k := range keys {
		if current == nil {
			return ""
		}
		if i == len(keys)-1 {
			if s, ok := current[k].(string); ok {
				return s
			}
			return ""
		}
		next, ok := current[k].(map[string]interface{})
		if !ok {
			return ""
		}
		current = next
	}
	return ""
}

func getNestedValue(m map[string]interface{}, keys ...string) interface{} {
	current := m
	for i, k := range keys {
		if current == nil {
			return nil
		}
		if i == len(keys)-1 {
			return current[k]
		}
		next, ok := current[k].(map[string]interface{})
		if !ok {
			return nil
		}
		current = next
	}
	return nil
}

func getInterfaceIP(iface map[string]interface{}) string {
	// Try different paths for IPv4 address
	subifs := getSlice(iface, "subinterfaces")
	if subifs == nil {
		subifs = getSlice(getNestedMap(iface, "subinterfaces"), "subinterface")
	}
	for _, subif := range subifs {
		// Try with and without prefix
		for _, ipv4Key := range []string{"ipv4", "openconfig-if-ip:ipv4"} {
			ipv4 := getNestedMap(subif, ipv4Key)
			if ipv4 == nil {
				continue
			}
			addrs := getSlice(ipv4, "addresses")
			if addrs == nil {
				addrs = getSlice(getNestedMap(ipv4, "addresses"), "address")
			}
			for _, addr := range addrs {
				if ip, ok := addr["ip"].(string); ok {
					prefix := getNestedValue(addr, "config", "prefix-length")
					if prefix == nil {
						prefix = getNestedValue(addr, "config", "prefix_length")
					}
					if prefix != nil {
						return fmt.Sprintf("%s/%v", ip, prefix)
					}
					return ip
				}
			}
		}
	}
	return ""
}

func getBGPNeighbors(m map[string]interface{}) map[string]map[string]interface{} {
	nbrs := getMapAnyKey(m, "neighbors")
	if nbrs == nil {
		return nil
	}
	return getListByName(nbrs, "neighbor", "neighbor-address")
}

func getBGPPeerGroups(m map[string]interface{}) map[string]map[string]interface{} {
	pgs := getMapAnyKey(m, "peer-groups")
	if pgs == nil {
		return nil
	}
	return getListByName(pgs, "peer-group", "peer-group-name")
}

// diffSystem compares system config
func diffSystem(path string, current, desired map[string]interface{}) []string {
	var diffs []string

	if strings.HasSuffix(path, "/config") {
		// Compare hostname
		cHost := getValueAnyKey(current, "hostname")
		dHost := getValueAnyKey(desired, "hostname")
		if dHost != nil && fmt.Sprintf("%v", dHost) != fmt.Sprintf("%v", cHost) {
			diffs = append(diffs, fmt.Sprintf("~ system hostname: %v → %v", cHost, dHost))
		}
	}

	if strings.HasSuffix(path, "/aaa") {
		// AAA config - just check if structure matches at high level
		// For now, assume in sync if both exist
	}

	if strings.HasSuffix(path, "/ntp") {
		// Compare NTP servers
		cServers := getNTPServers(current)
		dServers := getNTPServers(desired)
		for addr := range dServers {
			if _, exists := cServers[addr]; !exists {
				diffs = append(diffs, fmt.Sprintf("+ ntp server %s", addr))
			}
		}
	}

	if strings.HasSuffix(path, "/dns") {
		// Compare DNS servers
		cServers := getDNSServers(current)
		dServers := getDNSServers(desired)
		for _, addr := range dServers {
			found := false
			for _, c := range cServers {
				if c == addr {
					found = true
					break
				}
			}
			if !found {
				diffs = append(diffs, fmt.Sprintf("+ dns server %s", addr))
			}
		}
	}

	return diffs
}

func getValueAnyKey(m map[string]interface{}, key string) interface{} {
	if m == nil {
		return nil
	}
	if v := m[key]; v != nil {
		return v
	}
	for k, v := range m {
		if strings.HasSuffix(k, ":"+key) {
			return v
		}
	}
	return nil
}

func getNTPServers(m map[string]interface{}) map[string]bool {
	result := make(map[string]bool)
	servers := getMapAnyKey(m, "servers")
	if servers == nil {
		return result
	}
	list := getSliceAnyKey(servers, "server")
	for _, srv := range list {
		if addr, ok := srv["address"].(string); ok {
			result[addr] = true
		}
	}
	return result
}

func getDNSServers(m map[string]interface{}) []string {
	var result []string
	servers := getMapAnyKey(m, "servers")
	if servers == nil {
		return result
	}
	list := getSliceAnyKey(servers, "server")
	for _, srv := range list {
		if addr, ok := srv["address"].(string); ok {
			result = append(result, addr)
		}
	}
	return result
}

// diffRoutingPolicy compares routing policy config
func diffRoutingPolicy(current, desired map[string]interface{}) []string {
	var diffs []string

	// Compare policy definitions
	cPolicies := getPolicyDefinitions(current)
	dPolicies := getPolicyDefinitions(desired)
	for name := range dPolicies {
		if _, exists := cPolicies[name]; !exists {
			diffs = append(diffs, fmt.Sprintf("+ policy %s", name))
		}
	}
	for name := range cPolicies {
		if _, exists := dPolicies[name]; !exists {
			diffs = append(diffs, fmt.Sprintf("- policy %s (not in model)", name))
		}
	}

	// Compare prefix sets
	cPrefixSets := getPrefixSets(current)
	dPrefixSets := getPrefixSets(desired)
	for name := range dPrefixSets {
		if _, exists := cPrefixSets[name]; !exists {
			diffs = append(diffs, fmt.Sprintf("+ prefix-set %s", name))
		}
	}
	for name := range cPrefixSets {
		if _, exists := dPrefixSets[name]; !exists {
			diffs = append(diffs, fmt.Sprintf("- prefix-set %s (not in model)", name))
		}
	}

	// Compare community sets
	cCommSets := getCommunitySets(current)
	dCommSets := getCommunitySets(desired)
	for name := range dCommSets {
		if _, exists := cCommSets[name]; !exists {
			diffs = append(diffs, fmt.Sprintf("+ community-set %s", name))
		}
	}
	for name := range cCommSets {
		if _, exists := dCommSets[name]; !exists {
			diffs = append(diffs, fmt.Sprintf("- community-set %s (not in model)", name))
		}
	}

	return diffs
}

func getPolicyDefinitions(m map[string]interface{}) map[string]bool {
	result := make(map[string]bool)
	
	// Try OpenConfig structure: policy-definitions/policy-definition
	defs := getMapAnyKey(m, "policy-definitions")
	if defs != nil {
		list := getSliceAnyKey(defs, "policy-definition")
		for _, p := range list {
			name := getStringAnyKey(p, "name")
			if name != "" {
				result[name] = true
			}
		}
	}
	
	// Try YAML structure: policy_definitions (direct list)
	list := getSliceAnyKey(m, "policy-definitions")
	if list == nil {
		list = getSliceAnyKey(m, "policy_definitions")
	}
	for _, p := range list {
		name := getStringAnyKey(p, "name")
		if name != "" {
			result[name] = true
		}
	}
	
	return result
}

func getPrefixSets(m map[string]interface{}) map[string]bool {
	result := make(map[string]bool)
	defs := getMapAnyKey(m, "defined-sets")
	if defs == nil {
		return result
	}
	
	// Try OpenConfig structure: defined-sets/prefix-sets/prefix-set
	prefixSets := getMapAnyKey(defs, "prefix-sets")
	if prefixSets != nil {
		list := getSliceAnyKey(prefixSets, "prefix-set")
		for _, p := range list {
			name := getStringAnyKey(p, "name")
			if name != "" {
				result[name] = true
			}
		}
	}
	
	// Try YAML structure: defined_sets/prefix_sets (direct list)
	list := getSliceAnyKey(defs, "prefix-sets")
	if list == nil {
		list = getSliceAnyKey(defs, "prefix_sets")
	}
	for _, p := range list {
		name := getStringAnyKey(p, "name")
		if name != "" {
			result[name] = true
		}
	}
	
	return result
}

func getCommunitySets(m map[string]interface{}) map[string]bool {
	result := make(map[string]bool)
	defs := getMapAnyKey(m, "defined-sets")
	if defs == nil {
		return result
	}
	bgpDefs := getMapAnyKey(defs, "bgp-defined-sets")
	if bgpDefs == nil {
		return result
	}
	commSets := getMapAnyKey(bgpDefs, "community-sets")
	if commSets == nil {
		return result
	}
	list := getSliceAnyKey(commSets, "community-set")
	for _, c := range list {
		if name, ok := c["community-set-name"].(string); ok {
			result[name] = true
		}
	}
	return result
}

// getMapAnyKey gets a map from parent, trying various key formats
func getMapAnyKey(m map[string]interface{}, key string) map[string]interface{} {
	if m == nil {
		return nil
	}
	// Try exact key first
	if v, ok := m[key].(map[string]interface{}); ok {
		return v
	}
	// Try with underscores converted to dashes and vice versa
	altKey := strings.ReplaceAll(key, "-", "_")
	if v, ok := m[altKey].(map[string]interface{}); ok {
		return v
	}
	altKey = strings.ReplaceAll(key, "_", "-")
	if v, ok := m[altKey].(map[string]interface{}); ok {
		return v
	}
	// Try with common prefixes
	for k, v := range m {
		if strings.HasSuffix(k, ":"+key) {
			if vm, ok := v.(map[string]interface{}); ok {
				return vm
			}
		}
	}
	return nil
}

// getNestedMapAny navigates nested maps trying prefixed keys at each level
func getNestedMapAny(m map[string]interface{}, keys ...string) map[string]interface{} {
	current := m
	for _, k := range keys {
		current = getMapAnyKey(current, k)
		if current == nil {
			return nil
		}
	}
	return current
}

// toMap converts interface{} to map if possible
func toMap(v interface{}) map[string]interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return nil
}

// normalizeMap normalizes keys for comparison (strips prefixes, converts dashes)
func normalizeMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	result := make(map[string]interface{})
	for k, v := range m {
		// Strip OpenConfig prefixes like "openconfig-interfaces:"
		key := k
		if idx := strings.LastIndex(k, ":"); idx != -1 {
			key = k[idx+1:]
		}
		// Normalize dashes to underscores
		key = strings.ReplaceAll(key, "-", "_")

		switch val := v.(type) {
		case map[string]interface{}:
			result[key] = normalizeMap(val)
		case []interface{}:
			result[key] = normalizeSlice(val)
		default:
			result[key] = v
		}
	}
	return result
}

func normalizeSlice(s []interface{}) []interface{} {
	result := make([]interface{}, len(s))
	for i, v := range s {
		if m, ok := v.(map[string]interface{}); ok {
			result[i] = normalizeMap(m)
		} else {
			result[i] = v
		}
	}
	return result
}

// findDiffs finds what in 'desired' differs from 'current'
// Only reports things in desired that are missing or different in current
func findDiffs(current, desired map[string]interface{}, prefix string) []string {
	if desired == nil {
		return nil
	}

	var diffs []string

	for k, dv := range desired {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}

		cv, exists := current[k]
		if !exists {
			diffs = append(diffs, fmt.Sprintf("+ %s: %s", path, formatValue(dv)))
			continue
		}

		// Both maps - recurse
		dm, dIsMap := dv.(map[string]interface{})
		cm, cIsMap := cv.(map[string]interface{})
		if dIsMap && cIsMap {
			diffs = append(diffs, findDiffs(cm, dm, path)...)
			continue
		}

		// Both slices - compare by key field (name, ip, etc.)
		ds := toSlice(dv)
		cs := toSlice(cv)
		if ds != nil && cs != nil {
			diffs = append(diffs, findSliceDiffs(cs, ds, path)...)
			continue
		}

		// Scalar comparison
		if fmt.Sprintf("%v", cv) != fmt.Sprintf("%v", dv) {
			diffs = append(diffs, fmt.Sprintf("~ %s: %v → %v", path, formatValue(cv), formatValue(dv)))
		}
	}

	return diffs
}

// toSlice converts various slice types to []map[string]interface{}
func toSlice(v interface{}) []map[string]interface{} {
	switch s := v.(type) {
	case []interface{}:
		result := make([]map[string]interface{}, 0, len(s))
		for _, item := range s {
			if m, ok := item.(map[string]interface{}); ok {
				result = append(result, m)
			}
		}
		return result
	case []map[string]interface{}:
		return s
	default:
		return nil
	}
}

// findSliceDiffs compares slices by finding items by key
func findSliceDiffs(current, desired []map[string]interface{}, prefix string) []string {
	var diffs []string

	// Build map of current items by key
	currentByKey := make(map[string]map[string]interface{})
	for _, m := range current {
		key := getItemKey(m)
		if key != "" {
			currentByKey[key] = m
		}
	}

	// Check each desired item
	for _, dm := range desired {
		key := getItemKey(dm)
		if key == "" {
			continue
		}

		path := fmt.Sprintf("%s[%s]", prefix, key)
		cm, exists := currentByKey[key]
		if !exists {
			diffs = append(diffs, fmt.Sprintf("+ %s", path))
			continue
		}

		// Compare the items (recursively, but limit depth for readability)
		itemDiffs := findDiffs(cm, dm, "")
		for _, d := range itemDiffs {
			diffs = append(diffs, fmt.Sprintf("%s: %s", path, d))
		}
	}

	return diffs
}

// getItemKey extracts the key field from a list item
func getItemKey(m map[string]interface{}) string {
	// Common key fields in OpenConfig
	for _, key := range []string{"name", "ip", "index", "neighbor_address", "peer_group_name", "afi_safi_name"} {
		if v, ok := m[key]; ok {
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

// formatValue formats a value for display
func formatValue(v interface{}) string {
	switch val := v.(type) {
	case map[string]interface{}:
		if len(val) <= 2 {
			return fmt.Sprintf("%v", val)
		}
		return fmt.Sprintf("{%d keys}", len(val))
	case []interface{}:
		return fmt.Sprintf("[%d items]", len(val))
	default:
		return fmt.Sprintf("%v", val)
	}
}

// summarizeValue creates a brief summary of a config value
func summarizeValue(v interface{}) string {
	switch val := v.(type) {
	case map[string]interface{}:
		// Check for interface list
		if ifaces, ok := val["interface"]; ok {
			count := countList(ifaces)
			if count > 0 {
				return fmt.Sprintf("(%d interfaces)", count)
			}
		}
		// Check for peer-group list  
		if pgs, ok := val["peer-groups"]; ok {
			if pgsMap, ok := pgs.(map[string]interface{}); ok {
				if pgList, ok := pgsMap["peer-group"]; ok {
					count := countList(pgList)
					if count > 0 {
						return fmt.Sprintf("(%d peer-groups)", count)
					}
				}
			}
		}
		// Check for neighbor list
		if nbrs, ok := val["neighbors"]; ok {
			if nbrsMap, ok := nbrs.(map[string]interface{}); ok {
				if nbrList, ok := nbrsMap["neighbor"]; ok {
					count := countList(nbrList)
					if count > 0 {
						return fmt.Sprintf("(%d neighbors)", count)
					}
				}
			}
		}
		// BGP global
		if _, ok := val["global"]; ok {
			parts := []string{}
			if _, hasGlobal := val["global"]; hasGlobal {
				parts = append(parts, "global")
			}
			if pgs, ok := val["peer-groups"].(map[string]interface{}); ok {
				if pgList, ok := pgs["peer-group"]; ok {
					parts = append(parts, fmt.Sprintf("%d peer-groups", countList(pgList)))
				}
			}
			if nbrs, ok := val["neighbors"].(map[string]interface{}); ok {
				if nbrList, ok := nbrs["neighbor"]; ok {
					parts = append(parts, fmt.Sprintf("%d neighbors", countList(nbrList)))
				}
			}
			if len(parts) > 0 {
				return fmt.Sprintf("(%s)", joinParts(parts))
			}
		}
		return fmt.Sprintf("(%d keys)", len(val))
	case []interface{}:
		return fmt.Sprintf("(%d items)", len(val))
	case []map[string]interface{}:
		return fmt.Sprintf("(%d items)", len(val))
	default:
		return fmt.Sprintf("= %v", val)
	}
}

func countList(v interface{}) int {
	switch list := v.(type) {
	case []interface{}:
		return len(list)
	case []map[string]interface{}:
		return len(list)
	default:
		return 0
	}
}

func joinParts(parts []string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += ", "
		}
		result += p
	}
	return result
}

func countDefinedSets(m map[string]interface{}) int {
	count := 0
	for _, v := range m {
		if vm, ok := v.(map[string]interface{}); ok {
			for _, v2 := range vm {
				if list, ok := v2.([]interface{}); ok {
					count += len(list)
				}
			}
		}
	}
	return count
}

// Delete removes specific paths
func (a *Applier) Delete(ctx context.Context, paths []string) error {
	if a.dryRun {
		fmt.Println("Dry run - would delete:")
		for _, p := range paths {
			fmt.Printf("  - %s\n", p)
		}
		return nil
	}

	resp, err := a.client.Delete(ctx, paths)
	if err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	fmt.Printf("Deleted %d paths (timestamp: %d)\n", len(paths), resp.Timestamp)
	return nil
}

// ApplyFile applies (merges) config from a YAML file
func (a *Applier) ApplyFile(ctx context.Context, path string) error {
	data, err := a.loadFile(path)
	if err != nil {
		return fmt.Errorf("load file: %w", err)
	}
	return a.Apply(ctx, data)
}

// DiffFile diffs config from a YAML file
func (a *Applier) DiffFile(ctx context.Context, path string) error {
	data, err := a.loadFile(path)
	if err != nil {
		return fmt.Errorf("load file: %w", err)
	}
	return a.Diff(ctx, data)
}

// ApplyDir applies (merges) config from all YAML files in a directory
func (a *Applier) ApplyDir(ctx context.Context, dir string) error {
	combined, err := a.loadDir(dir)
	if err != nil {
		return err
	}
	return a.Apply(ctx, combined)
}

// DiffDir diffs config from all YAML files in a directory
func (a *Applier) DiffDir(ctx context.Context, dir string) error {
	combined, err := a.loadDir(dir)
	if err != nil {
		return err
	}
	return a.Diff(ctx, combined)
}

// LoadDir loads all YAML files from a directory
func (a *Applier) LoadDir(ctx context.Context, dir string) (map[string]interface{}, error) {
	return a.loadDir(dir)
}

// LoadFile loads a single YAML file
func (a *Applier) LoadFile(ctx context.Context, path string) (map[string]interface{}, error) {
	return a.loadFile(path)
}

func (a *Applier) loadDir(dir string) (map[string]interface{}, error) {
	combined := make(map[string]interface{})

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		data, err := a.loadFile(path)
		if err != nil {
			continue
		}

		// Merge into combined
		for k, v := range data {
			combined[k] = v
		}
	}

	return combined, nil
}

func (a *Applier) loadFile(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := yaml.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// buildUpdates converts YAML data to gNMI updates
func (a *Applier) buildUpdates(data map[string]interface{}) []*gnmi.Update {
	var updates []*gnmi.Update

	for key, value := range data {
		// Skip metadata
		if key == "metadata" {
			continue
		}

		// Handle system specially - can't replace entire /system
		if key == "system" {
			if sysData, ok := value.(map[string]interface{}); ok {
				updates = append(updates, systemSubPaths(sysData)...)
			}
			continue
		}

		path := featureToPath(key)
		if path == "" {
			continue
		}

		// Transform netmodel format to OpenConfig format
		transformed, err := transform.ToOpenConfig(key, value)
		if err != nil {
			fmt.Printf("Warning: failed to transform %s: %v\n", key, err)
			continue
		}

		updates = append(updates, &gnmi.Update{
			Path:  path,
			Value: transformed,
		})
	}

	return updates
}

// featureToPath maps netmodel feature names to OpenConfig paths
func featureToPath(feature string) string {
	paths := map[string]string{
		"interfaces":     "/interfaces",
		"bgp":            "/network-instances/network-instance[name=default]/protocols/protocol[identifier=BGP][name=BGP]/bgp",
		"ospf":           "/network-instances/network-instance[name=default]/protocols/protocol[identifier=OSPF][name=OSPF]/ospfv2",
		"routing_policy": "/routing-policy",
		"evpn":           "/network-instances/network-instance[name=default]/evpn",
	}

	return paths[feature]
}

// systemSubPaths returns the paths to update for system config
// We can't replace /system as it contains operational state
func systemSubPaths(data map[string]interface{}) []*gnmi.Update {
	var updates []*gnmi.Update

	if hostname, ok := data["hostname"]; ok {
		updates = append(updates, &gnmi.Update{
			Path:  "/system/config",
			Value: map[string]interface{}{"hostname": hostname},
		})
	}

	if aaa, ok := data["aaa"]; ok {
		transformed, _ := transform.ToOpenConfig("aaa", aaa)
		updates = append(updates, &gnmi.Update{
			Path:  "/system/aaa",
			Value: transformed,
		})
	}

	if ntp, ok := data["ntp"]; ok {
		transformed, _ := transform.ToOpenConfig("ntp", ntp)
		updates = append(updates, &gnmi.Update{
			Path:  "/system/ntp",
			Value: transformed,
		})
	}

	if dns, ok := data["dns"]; ok {
		transformed, _ := transform.ToOpenConfig("dns", dns)
		updates = append(updates, &gnmi.Update{
			Path:  "/system/dns",
			Value: transformed,
		})
	}

	return updates
}
