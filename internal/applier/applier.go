// Package applier converts netmodel YAML to gNMI Set operations
package applier

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ndtobs/netpush/internal/gnmi"
	"gopkg.in/yaml.v3"
)

// Operation type for Set
type Operation string

const (
	OpUpdate  Operation = "update"  // Merge with existing config
	OpReplace Operation = "replace" // Replace entire subtree
	OpDelete  Operation = "delete"  // Remove config
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

// ApplyFile applies config from a YAML file
func (a *Applier) ApplyFile(ctx context.Context, path string, op Operation) error {
	data, err := a.loadFile(path)
	if err != nil {
		return fmt.Errorf("load file: %w", err)
	}

	return a.Apply(ctx, data, op)
}

// ApplyDir applies config from all YAML files in a directory
func (a *Applier) ApplyDir(ctx context.Context, dir string, op Operation) error {
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
		if err := a.ApplyFile(ctx, path, op); err != nil {
			return fmt.Errorf("apply %s: %w", entry.Name(), err)
		}
	}

	return nil
}

// Apply pushes config data via gNMI
func (a *Applier) Apply(ctx context.Context, data map[string]interface{}, op Operation) error {
	updates := a.buildUpdates(data)

	if a.dryRun {
		fmt.Println("Dry run - would apply:")
		for _, u := range updates {
			fmt.Printf("  %s: %v\n", u.Path, u.Value)
		}
		return nil
	}

	switch op {
	case OpUpdate:
		resp, err := a.client.Set(ctx, updates)
		if err != nil {
			return fmt.Errorf("set: %w", err)
		}
		fmt.Printf("Applied %d updates (timestamp: %d)\n", len(updates), resp.Timestamp)

	case OpReplace:
		resp, err := a.client.Replace(ctx, updates)
		if err != nil {
			return fmt.Errorf("replace: %w", err)
		}
		fmt.Printf("Replaced %d paths (timestamp: %d)\n", len(updates), resp.Timestamp)

	case OpDelete:
		var paths []string
		for _, u := range updates {
			paths = append(paths, u.Path)
		}
		resp, err := a.client.Delete(ctx, paths)
		if err != nil {
			return fmt.Errorf("delete: %w", err)
		}
		fmt.Printf("Deleted %d paths (timestamp: %d)\n", len(paths), resp.Timestamp)
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
		path := featureToPath(key)
		if path == "" {
			continue
		}

		updates = append(updates, &gnmi.Update{
			Path:  path,
			Value: value,
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
		"system":         "/system",
		"routing_policy": "/routing-policy",
		"evpn":           "/network-instances/network-instance[name=default]/evpn",
	}

	return paths[feature]
}

// SyncResult contains the diff analysis
type SyncResult struct {
	Adds    []*gnmi.Update // New config to add
	Updates []*gnmi.Update // Changed config to update
	Deletes []string       // Paths to delete
}

// Sync compares local YAML to device state and applies minimal changes
func (a *Applier) Sync(ctx context.Context, data map[string]interface{}) (*SyncResult, error) {
	result := &SyncResult{}

	for feature, desired := range data {
		path := featureToPath(feature)
		if path == "" {
			continue
		}

		// Get current config from device
		current, err := a.client.GetJSON(ctx, path)
		if err != nil {
			// Path doesn't exist = need to create
			result.Adds = append(result.Adds, &gnmi.Update{
				Path:  path,
				Value: desired,
			})
			continue
		}

		// Compare and build diff
		desiredMap, ok := desired.(map[string]interface{})
		if !ok {
			continue
		}

		adds, updates, deletes := diffMaps(path, current, desiredMap)
		result.Adds = append(result.Adds, adds...)
		result.Updates = append(result.Updates, updates...)
		result.Deletes = append(result.Deletes, deletes...)
	}

	return result, nil
}

// ApplySync applies a sync result
func (a *Applier) ApplySync(ctx context.Context, result *SyncResult) error {
	if a.dryRun {
		fmt.Println("Dry run - would apply:")
		for _, add := range result.Adds {
			fmt.Printf("  ADD: %s\n", add.Path)
		}
		for _, upd := range result.Updates {
			fmt.Printf("  UPDATE: %s\n", upd.Path)
		}
		for _, del := range result.Deletes {
			fmt.Printf("  DELETE: %s\n", del)
		}
		if len(result.Adds) == 0 && len(result.Updates) == 0 && len(result.Deletes) == 0 {
			fmt.Println("  (no changes)")
		}
		return nil
	}

	// Apply deletes first
	if len(result.Deletes) > 0 {
		_, err := a.client.Delete(ctx, result.Deletes)
		if err != nil {
			return fmt.Errorf("delete: %w", err)
		}
		fmt.Printf("Deleted %d paths\n", len(result.Deletes))
	}

	// Apply adds/updates together
	allUpdates := append(result.Adds, result.Updates...)
	if len(allUpdates) > 0 {
		_, err := a.client.Set(ctx, allUpdates)
		if err != nil {
			return fmt.Errorf("set: %w", err)
		}
		fmt.Printf("Applied %d adds, %d updates\n", len(result.Adds), len(result.Updates))
	}

	if len(result.Adds) == 0 && len(result.Updates) == 0 && len(result.Deletes) == 0 {
		fmt.Println("No changes needed")
	}

	return nil
}

// SyncFile syncs config from a YAML file
func (a *Applier) SyncFile(ctx context.Context, path string) error {
	data, err := a.loadFile(path)
	if err != nil {
		return fmt.Errorf("load file: %w", err)
	}

	result, err := a.Sync(ctx, data)
	if err != nil {
		return err
	}

	return a.ApplySync(ctx, result)
}

// SyncDir syncs config from all YAML files in a directory
func (a *Applier) SyncDir(ctx context.Context, dir string) error {
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
		if err := a.SyncFile(ctx, path); err != nil {
			return fmt.Errorf("sync %s: %w", entry.Name(), err)
		}
	}

	return nil
}

// diffMaps compares two maps and returns adds, updates, deletes
func diffMaps(basePath string, current, desired map[string]interface{}) ([]*gnmi.Update, []*gnmi.Update, []string) {
	var adds, updates []*gnmi.Update
	var deletes []string

	// Find additions and updates
	for key, desiredVal := range desired {
		currentVal, exists := current[key]
		if !exists {
			// New key - add
			adds = append(adds, &gnmi.Update{
				Path:  basePath + "/" + key,
				Value: desiredVal,
			})
			continue
		}

		// Check if value changed
		if !deepEqual(currentVal, desiredVal) {
			updates = append(updates, &gnmi.Update{
				Path:  basePath + "/" + key,
				Value: desiredVal,
			})
		}
	}

	// Find deletions
	for key := range current {
		if _, exists := desired[key]; !exists {
			deletes = append(deletes, basePath+"/"+key)
		}
	}

	return adds, updates, deletes
}

// deepEqual compares two values
func deepEqual(a, b interface{}) bool {
	// Simple comparison - could be enhanced
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}
