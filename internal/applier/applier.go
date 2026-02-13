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

	if a.dryRun {
		fmt.Println("Dry run - would merge:")
		for _, u := range updates {
			fmt.Printf("  UPDATE: %s\n", u.Path)
		}
		if len(updates) == 0 {
			fmt.Println("  (no changes)")
		}
		return nil
	}

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

// Sync replaces config (gNMI Replace - makes device match YAML exactly)
func (a *Applier) Sync(ctx context.Context, data map[string]interface{}) error {
	updates := a.buildUpdates(data)

	if a.dryRun {
		fmt.Println("Would replace:")
		for _, u := range updates {
			fmt.Printf("  REPLACE: %s\n", u.Path)
		}
		if len(updates) == 0 {
			fmt.Println("  (nothing to sync)")
		}
		return nil
	}

	if len(updates) == 0 {
		fmt.Println("No config to sync")
		return nil
	}

	resp, err := a.client.Replace(ctx, updates)
	if err != nil {
		return fmt.Errorf("replace: %w", err)
	}
	fmt.Printf("Replaced %d paths (timestamp: %d)\n", len(updates), resp.Timestamp)
	return nil
}

// Diff compares YAML to device state and shows differences
func (a *Applier) Diff(ctx context.Context, data map[string]interface{}) error {
	updates := a.buildUpdates(data)

	hasChanges := false
	for _, u := range updates {
		current, err := a.client.GetJSON(ctx, u.Path)
		if err != nil {
			fmt.Printf("  %s: (new or cannot read)\n", u.Path)
			hasChanges = true
			continue
		}

		desiredMap, ok := u.Value.(map[string]interface{})
		if !ok {
			fmt.Printf("  %s: (type mismatch)\n", u.Path)
			hasChanges = true
			continue
		}

		diff := diffConfig(current, desiredMap)
		if diff != "" {
			fmt.Printf("  %s:\n%s", u.Path, diff)
			hasChanges = true
		}
	}
	if !hasChanges {
		fmt.Println("  (no differences)")
	}
	return nil
}

// DiffFile diffs config from a YAML file
func (a *Applier) DiffFile(ctx context.Context, path string) error {
	data, err := a.loadFile(path)
	if err != nil {
		return fmt.Errorf("load file: %w", err)
	}
	return a.Diff(ctx, data)
}

// DiffDir diffs config from all YAML files in a directory
func (a *Applier) DiffDir(ctx context.Context, dir string) error {
	return a.processDir(ctx, dir, a.Diff)
}

// Delete removes specific paths
func (a *Applier) Delete(ctx context.Context, paths []string) error {
	if a.dryRun {
		fmt.Println("Dry run - would delete:")
		for _, p := range paths {
			fmt.Printf("  DELETE: %s\n", p)
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

// SyncFile syncs (replaces) config from a YAML file
func (a *Applier) SyncFile(ctx context.Context, path string) error {
	data, err := a.loadFile(path)
	if err != nil {
		return fmt.Errorf("load file: %w", err)
	}
	return a.Sync(ctx, data)
}

// ApplyDir applies (merges) config from all YAML files in a directory
func (a *Applier) ApplyDir(ctx context.Context, dir string) error {
	return a.processDir(ctx, dir, a.Apply)
}

// SyncDir syncs (replaces) config from all YAML files in a directory
func (a *Applier) SyncDir(ctx context.Context, dir string) error {
	return a.processDir(ctx, dir, a.Sync)
}

func (a *Applier) processDir(ctx context.Context, dir string, fn func(context.Context, map[string]interface{}) error) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read dir: %w", err)
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
			return fmt.Errorf("load %s: %w", entry.Name(), err)
		}

		if err := fn(ctx, data); err != nil {
			return fmt.Errorf("%s: %w", entry.Name(), err)
		}
	}

	return nil
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
			Path:  "/system/config/hostname",
			Value: hostname,
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

// diffConfig compares two configs and returns a human-readable diff
func diffConfig(current, desired map[string]interface{}) string {
	var sb strings.Builder

	// Find additions and changes in desired
	for key, desiredVal := range desired {
		currentVal, exists := current[key]
		if !exists {
			sb.WriteString(fmt.Sprintf("    + %s\n", key))
			continue
		}

		if !deepEqual(currentVal, desiredVal) {
			sb.WriteString(fmt.Sprintf("    ~ %s\n", key))
		}
	}

	// Find deletions (in current but not in desired)
	for key := range current {
		if _, exists := desired[key]; !exists {
			sb.WriteString(fmt.Sprintf("    - %s\n", key))
		}
	}

	return sb.String()
}

// deepEqual compares two values recursively
func deepEqual(a, b interface{}) bool {
	// Handle nil cases
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// Both maps
	aMap, aIsMap := a.(map[string]interface{})
	bMap, bIsMap := b.(map[string]interface{})
	if aIsMap && bIsMap {
		if len(aMap) != len(bMap) {
			return false
		}
		for k, av := range aMap {
			bv, ok := bMap[k]
			if !ok || !deepEqual(av, bv) {
				return false
			}
		}
		return true
	}

	// Both slices
	aSlice, aIsSlice := a.([]interface{})
	bSlice, bIsSlice := b.([]interface{})
	if aIsSlice && bIsSlice {
		if len(aSlice) != len(bSlice) {
			return false
		}
		for i := range aSlice {
			if !deepEqual(aSlice[i], bSlice[i]) {
				return false
			}
		}
		return true
	}

	// Scalar comparison
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}
