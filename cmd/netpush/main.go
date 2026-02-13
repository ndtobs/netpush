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
	rootCmd.AddCommand(syncCmd())
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

  # Preview changes
  netpush apply ./model/ -i inventory.yaml --dry-run`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(args[0], target, inventoryFile, group, username, password, insecure, dryRun, timeout, "apply")
		},
	}

	addCommonFlags(cmd, &target, &inventoryFile, &group, &username, &password, &insecure, &timeout)
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview changes without applying")

	return cmd
}

func syncCmd() *cobra.Command {
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
		Use:   "sync <path>",
		Short: "Sync config (replace, device matches YAML exactly)",
		Long: `Sync network configuration via gNMI Replace.

Makes device config match your YAML exactly for each feature.
If something exists on the device but not in your YAML, it gets removed.

To remove a BGP neighbor: delete it from YAML, run sync.
To remove an interface: delete it from YAML, run sync.

Examples:
  # Sync single device
  netpush sync ./host_vars/leaf1/ -t leaf1:6030 -u admin -P admin -k

  # Sync using inventory
  netpush sync ./model/ -i inventory.yaml

  # Always preview first!
  netpush sync ./model/ -i inventory.yaml --dry-run`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(args[0], target, inventoryFile, group, username, password, insecure, dryRun, timeout, "sync")
		},
	}

	addCommonFlags(cmd, &target, &inventoryFile, &group, &username, &password, &insecure, &timeout)
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview changes without applying")

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
		Short: "Show differences between YAML and device config",
		Long: `Compare YAML config to device state and show differences.

Shows what's different without making any changes.

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

// run executes apply or sync
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

		configPath := findHostConfig(basePath, host)
		fmt.Printf("\n=== %s (%s) ===\n", host, target)

		if err := runSingle(configPath, target, hostUser, hostPass, hostInsecure, dryRun, timeout, op); err != nil {
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

func findHostConfig(basePath, host string) string {
	// Check for host_vars/<host>/
	hostVars := filepath.Join(basePath, "host_vars", host)
	if info, err := os.Stat(hostVars); err == nil && info.IsDir() {
		return hostVars
	}

	// Check for group_vars/ (common config)
	groupVars := filepath.Join(basePath, "group_vars")
	if info, err := os.Stat(groupVars); err == nil && info.IsDir() {
		return groupVars
	}

	return basePath
}

func runSingle(configPath, target, username, password string, insecure, dryRun bool, timeout time.Duration, op string) error {
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

	info, err := os.Stat(configPath)
	if err != nil {
		return err
	}

	switch op {
	case "apply":
		if info.IsDir() {
			return app.ApplyDir(ctx, configPath)
		}
		return app.ApplyFile(ctx, configPath)
	case "sync":
		if info.IsDir() {
			return app.SyncDir(ctx, configPath)
		}
		return app.SyncFile(ctx, configPath)
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
