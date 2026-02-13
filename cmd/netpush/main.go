package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ndtobs/netpush/internal/applier"
	"github.com/ndtobs/netpush/internal/inventory"
	"github.com/spf13/cobra"
)

var version = "0.1.0"

func main() {
	rootCmd := &cobra.Command{
		Use:     "netpush",
		Short:   "Push network config via gNMI from netmodel YAML",
		Version: version,
	}

	rootCmd.AddCommand(applyCmd())
	rootCmd.AddCommand(diffCmd())
	rootCmd.AddCommand(deleteCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func applyCmd() *cobra.Command {
	var (
		target        string
		inventoryFile string
		group         string
		username      string
		password      string
		insecure      bool
		dryRun        bool
		timeout       time.Duration
	)

	cmd := &cobra.Command{
		Use:   "apply <path>",
		Short: "Apply config (merge, additive only)",
		Long: `Apply network configuration via gNMI Update (merge semantics).

Adds and modifies config. Never removes anything.
This is the safe default for incremental changes.

Examples:
  # Apply to single device
  netpush apply ./host_vars/leaf1/ -t leaf1:6030 -u admin -P admin -k

  # Apply using inventory
  netpush apply ./model/ -i inventory.yaml

  # Preview changes (same as diff)
  netpush apply ./model/ -i inventory.yaml --dry-run`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(args[0], target, inventoryFile, group, username, password, insecure, dryRun, timeout, "apply")
		},
	}

	addCommonFlags(cmd, &target, &inventoryFile, &group, &username, &password, &insecure, &timeout)
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview changes without applying (same as diff)")

	return cmd
}

func diffCmd() *cobra.Command {
	var (
		target        string
		inventoryFile string
		group         string
		username      string
		password      string
		insecure      bool
		timeout       time.Duration
	)

	cmd := &cobra.Command{
		Use:   "diff <path>",
		Short: "Show what apply would change",
		Long: `Compare YAML config to device state and show what apply would change.

Shows additions and modifications without making any changes.

Output:
  + path: value       # would be added (not on device)
  ~ path: old → new   # would be changed

Examples:
  # Diff single device
  netpush diff ./host_vars/leaf1/ -t leaf1:6030 -u admin -P admin -k

  # Diff using inventory
  netpush diff ./model/ -i inventory.yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(args[0], target, inventoryFile, group, username, password, insecure, false, timeout, "diff")
		},
	}

	addCommonFlags(cmd, &target, &inventoryFile, &group, &username, &password, &insecure, &timeout)

	return cmd
}

func deleteCmd() *cobra.Command {
	var (
		target        string
		inventoryFile string
		group         string
		username      string
		password      string
		insecure      bool
		dryRun        bool
		paths         []string
		timeout       time.Duration
	)

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete specific paths",
		Long: `Delete specific OpenConfig paths via gNMI.

Examples:
  # Delete specific path
  netpush delete -p "interface[Ethernet5]" -t leaf1:6030 -u admin -P admin -k

  # Delete multiple paths
  netpush delete -p "interface[Vlan10]" -p "interface[Vlan20]" -t leaf1:6030 ...

  # Delete across inventory
  netpush delete -p "interface[Vlan99]" -i inventory.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(paths) == 0 {
				return fmt.Errorf("--path/-p required")
			}
			return runDelete(paths, target, inventoryFile, group, username, password, insecure, dryRun, timeout)
		},
	}

	addCommonFlags(cmd, &target, &inventoryFile, &group, &username, &password, &insecure, &timeout)
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview deletions without applying")
	cmd.Flags().StringArrayVarP(&paths, "path", "p", nil, "OpenConfig path to delete (can be repeated)")

	return cmd
}

func addCommonFlags(cmd *cobra.Command, target, inventoryFile, group, username, password *string, insecure *bool, timeout *time.Duration) {
	cmd.Flags().StringVarP(target, "target", "t", "", "target device (host:port)")
	cmd.Flags().StringVarP(inventoryFile, "inventory", "i", "", "inventory file")
	cmd.Flags().StringVarP(group, "group", "g", "", "target group from inventory")
	cmd.Flags().StringVarP(username, "username", "u", "", "gNMI username")
	cmd.Flags().StringVarP(password, "password", "P", "", "gNMI password")
	cmd.Flags().BoolVarP(insecure, "insecure", "k", false, "skip TLS verification")
	cmd.Flags().DurationVar(timeout, "timeout", 30*time.Second, "operation timeout")
}

// run executes apply or diff
func run(basePath, target, invFile, group, username, password string, insecure, dryRun bool, timeout time.Duration, op string) error {
	if invFile != "" {
		return runWithInventory(basePath, invFile, group, username, password, insecure, dryRun, timeout, op)
	}

	if target == "" {
		return fmt.Errorf("either --target or --inventory required")
	}

	return runSingle(basePath, target, username, password, insecure, dryRun, timeout, op)
}

// runWithInventory runs against inventory hosts
func runWithInventory(basePath, invFile, group, username, password string, insecure, dryRun bool, timeout time.Duration, op string) error {
	inv, err := inventory.Load(invFile)
	if err != nil {
		return fmt.Errorf("load inventory: %w", err)
	}

	hosts := getHosts(inv, group)
	if len(hosts) == 0 {
		return fmt.Errorf("no hosts found")
	}

	for _, host := range hosts {
		target := inv.ResolveHost(host)
		hostUser, hostPass, hostInsecure := inv.GetHostCredentials(host)
		if username != "" {
			hostUser = username
		}
		if password != "" {
			hostPass = password
		}
		if insecure {
			hostInsecure = true
		}

		hostGroups := inv.GetHostGroups(host)
		configPaths := findHostConfigs(basePath, host, target, hostGroups)
		fmt.Printf("\n=== %s (%s) ===\n", host, target)

		if err := runMultiple(configPaths, target, hostUser, hostPass, hostInsecure, dryRun, timeout, op); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}

	return nil
}

func getHosts(inv *inventory.Inventory, group string) []string {
	if group != "" {
		hosts, ok := inv.GetGroup(group)
		if !ok {
			return nil
		}
		return hosts
	}
	hosts, _ := inv.GetGroup("all")
	return hosts
}

// findHostConfigs returns all config paths for a host (group_vars + host_vars)
func findHostConfigs(basePath, host, target string, hostGroups []string) []string {
	var paths []string

	// Always include group_vars/all.yaml if it exists
	allVars := filepath.Join(basePath, "group_vars", "all.yaml")
	if _, err := os.Stat(allVars); err == nil {
		paths = append(paths, allVars)
	}

	// Include group_vars/<group>.yaml for each group the host belongs to
	groupVars := filepath.Join(basePath, "group_vars")
	if info, err := os.Stat(groupVars); err == nil && info.IsDir() {
		for _, group := range hostGroups {
			if group == "all" {
				continue // already loaded all.yaml
			}
			for _, ext := range []string{".yaml", ".yml"} {
				groupFile := filepath.Join(groupVars, group+ext)
				if _, err := os.Stat(groupFile); err == nil {
					paths = append(paths, groupFile)
					break
				}
			}
		}
	}

	// Check for host_vars/<host>/ (inventory name)
	hostVars := filepath.Join(basePath, "host_vars", host)
	if info, err := os.Stat(hostVars); err == nil && info.IsDir() {
		paths = append(paths, hostVars)
		return paths
	}

	// Check for host_vars/<address>/ (resolved address without port)
	addr := target
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		addr = target[:idx]
	}
	if addr != host {
		addrVars := filepath.Join(basePath, "host_vars", addr)
		if info, err := os.Stat(addrVars); err == nil && info.IsDir() {
			paths = append(paths, addrVars)
			return paths
		}
	}

	return paths
}

// runMultiple merges configs from multiple paths and runs the operation
func runMultiple(configPaths []string, target, username, password string, insecure, dryRun bool, timeout time.Duration, op string) error {
	if len(configPaths) == 0 {
		return fmt.Errorf("no config paths found")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	app, err := applier.New(applier.Config{
		Target:   target,
		Username: username,
		Password: password,
		Insecure: insecure,
	})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer app.Close()

	// Merge all configs (later paths override earlier ones - host_vars override group_vars)
	// Uses deep merge so nested keys are merged, not replaced
	merged := make(map[string]interface{})
	for _, path := range configPaths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.IsDir() {
			data, err := app.LoadDir(ctx, path)
			if err != nil {
				continue
			}
			deepMerge(merged, data)
		} else {
			data, err := app.LoadFile(ctx, path)
			if err != nil {
				continue
			}
			deepMerge(merged, data)
		}
	}

	if len(merged) == 0 {
		fmt.Println("No config found")
		return nil
	}

	switch op {
	case "apply":
		if dryRun {
			return app.Diff(ctx, merged)
		}
		return app.Apply(ctx, merged)
	case "diff":
		return app.Diff(ctx, merged)
	}

	return fmt.Errorf("unknown operation: %s", op)
}

// deepMerge merges src into dst, recursively merging nested maps
func deepMerge(dst, src map[string]interface{}) {
	for k, srcVal := range src {
		if dstVal, exists := dst[k]; exists {
			// Both exist - try to merge if both are maps
			srcMap, srcIsMap := srcVal.(map[string]interface{})
			dstMap, dstIsMap := dstVal.(map[string]interface{})
			if srcIsMap && dstIsMap {
				deepMerge(dstMap, srcMap)
				continue
			}
		}
		// Otherwise, src overwrites dst
		dst[k] = srcVal
	}
}

func runSingle(configPath, target, username, password string, insecure, dryRun bool, timeout time.Duration, op string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	app, err := applier.New(applier.Config{
		Target:   target,
		Username: username,
		Password: password,
		Insecure: insecure,
	})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer app.Close()

	info, err := os.Stat(configPath)
	if err != nil {
		return err
	}

	switch op {
	case "apply":
		if dryRun {
			// dry-run is just diff
			if info.IsDir() {
				return app.DiffDir(ctx, configPath)
			}
			return app.DiffFile(ctx, configPath)
		}
		if info.IsDir() {
			return app.ApplyDir(ctx, configPath)
		}
		return app.ApplyFile(ctx, configPath)
	case "diff":
		if info.IsDir() {
			return app.DiffDir(ctx, configPath)
		}
		return app.DiffFile(ctx, configPath)
	}

	return fmt.Errorf("unknown operation: %s", op)
}

// runDelete deletes specific paths
func runDelete(paths []string, target, invFile, group, username, password string, insecure, dryRun bool, timeout time.Duration) error {
	// Expand short paths
	expandedPaths := make([]string, len(paths))
	for i, p := range paths {
		expandedPaths[i] = expandPath(p)
	}

	if invFile != "" {
		return runDeleteWithInventory(expandedPaths, invFile, group, username, password, insecure, dryRun, timeout)
	}

	if target == "" {
		return fmt.Errorf("either --target or --inventory required")
	}

	return runDeleteSingle(expandedPaths, target, username, password, insecure, dryRun, timeout)
}

func runDeleteWithInventory(paths []string, invFile, group, username, password string, insecure, dryRun bool, timeout time.Duration) error {
	inv, err := inventory.Load(invFile)
	if err != nil {
		return fmt.Errorf("load inventory: %w", err)
	}

	hosts := getHosts(inv, group)
	if len(hosts) == 0 {
		return fmt.Errorf("no hosts found")
	}

	for _, host := range hosts {
		target := inv.ResolveHost(host)
		hostUser, hostPass, hostInsecure := inv.GetHostCredentials(host)
		if username != "" {
			hostUser = username
		}
		if password != "" {
			hostPass = password
		}
		if insecure {
			hostInsecure = true
		}

		fmt.Printf("\n=== %s (%s) ===\n", host, target)

		if err := runDeleteSingle(paths, target, hostUser, hostPass, hostInsecure, dryRun, timeout); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}

	return nil
}

func runDeleteSingle(paths []string, target, username, password string, insecure, dryRun bool, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	app, err := applier.New(applier.Config{
		Target:   target,
		Username: username,
		Password: password,
		Insecure: insecure,
		DryRun:   dryRun,
	})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer app.Close()

	return app.Delete(ctx, paths)
}

// expandPath expands short path syntax to full OpenConfig paths
func expandPath(path string) string {
	if len(path) > 0 && path[0] == '/' {
		return path
	}

	// bgp[<ni>]/... -> /network-instances/network-instance[name=<ni>]/protocols/protocol[identifier=BGP][name=BGP]/bgp/...
	if strings.HasPrefix(path, "bgp[") {
		rest := path[4:]
		if idx := strings.Index(rest, "]"); idx > 0 {
			ni := rest[:idx]
			remainder := rest[idx+1:]
			if strings.HasPrefix(remainder, "/") {
				remainder = remainder[1:]
			}
			return fmt.Sprintf("/network-instances/network-instance[name=%s]/protocols/protocol[identifier=BGP][name=BGP]/bgp/%s", ni, remainder)
		}
	}

	// interface[<name>]/... -> /interfaces/interface[name=<name>]/...
	if strings.HasPrefix(path, "interface[") {
		rest := path[10:]
		if idx := strings.Index(rest, "]"); idx > 0 {
			name := rest[:idx]
			remainder := rest[idx+1:]
			if strings.HasPrefix(remainder, "/") {
				remainder = remainder[1:]
			}
			if remainder == "" {
				return fmt.Sprintf("/interfaces/interface[name=%s]", name)
			}
			return fmt.Sprintf("/interfaces/interface[name=%s]/%s", name, remainder)
		}
	}

	// system/... -> /system/...
	if strings.HasPrefix(path, "system/") {
		return "/" + path
	}

	return "/" + path
}
