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
		fmt.Println("Dry run - would replace:")
		for _, u := range updates {
			fmt.Printf("  REPLACE: %s\n", u.Path)
		}
		if len(updates) == 0 {
			fmt.Println("  (no changes)")
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
