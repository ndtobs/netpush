package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
		Short: "Apply config (additive merge, no deletions)",
		Long: `Apply network configuration via gNMI.

Computes diff and applies only additions and updates.
Config on the device that's not in your YAML is left alone.
This is the safe default for most use cases.

Use 'sync' instead if you want full replacement (with deletions).

Examples:
  # Apply to single device
  netpush apply ./host_vars/leaf1/ -t leaf1:6030 -u admin -P admin -k

  # Apply using inventory
  netpush apply ./ -i inventory.yaml

  # Preview changes first
  netpush apply ./ -i inventory.yaml --dry-run`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(args[0], target, inventoryFile, group, username, password, insecure, dryRun, false, timeout)
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
		Short: "Sync config (full replacement, includes deletions)",
		Long: `Sync network configuration to exactly match your YAML.

Computes diff and applies additions, updates, AND deletions.
Config on the device that's not in your YAML WILL BE DELETED.

Use 'apply' instead if you only want additive changes.

Examples:
  # Sync single device
  netpush sync ./host_vars/leaf1/ -t leaf1:6030 -u admin -P admin -k

  # Sync using inventory
  netpush sync ./ -i inventory.yaml

  # Always preview first!
  netpush sync ./ -i inventory.yaml --dry-run`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(args[0], target, inventoryFile, group, username, password, insecure, dryRun, true, timeout)
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
		full          bool
		timeout       time.Duration
	)

	cmd := &cobra.Command{
		Use:   "diff <path>",
		Short: "Show diff between YAML and device config",
		Long: `Compare local YAML config with device's current config.

By default shows what 'apply' would do (additions and updates only).
Use --full to show what 'sync' would do (including deletions).

Examples:
  # Show additive changes
  netpush diff ./host_vars/leaf1/ -t leaf1:6030 -u admin -P admin -k

  # Show full diff including deletions
  netpush diff ./ -i inventory.yaml --full`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// diff is always dry-run
			return run(args[0], target, inventoryFile, group, username, password, insecure, true, full, timeout)
		},
	}

	addCommonFlags(cmd, &target, &inventoryFile, &group, &username, &password, &insecure, &timeout)
	cmd.Flags().BoolVar(&full, "full", false, "show deletions (what sync would do)")

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
		timeout       time.Duration
	)

	cmd := &cobra.Command{
		Use:   "delete <path>",
		Short: "Delete config specified in YAML",
		Long: `Delete network configuration via gNMI.

The YAML file specifies what paths to delete.

Examples:
  # Delete from single device
  netpush delete ./remove-peer.yaml -t leaf1:6030 -u admin -P admin -k

  # Delete using inventory
  netpush delete ./remove-peer.yaml -i inventory.yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDelete(args[0], target, inventoryFile, group, username, password, insecure, dryRun, timeout)
		},
	}

	addCommonFlags(cmd, &target, &inventoryFile, &group, &username, &password, &insecure, &timeout)
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview deletions without applying")

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

// run executes apply or sync against targets
func run(basePath, target, invFile, group, username, password string, insecure, dryRun, prune bool, timeout time.Duration) error {
	if invFile != "" {
		return runWithInventory(basePath, invFile, group, username, password, insecure, dryRun, prune, timeout)
	}

	if target == "" {
		return fmt.Errorf("either --target or --inventory required")
	}

	return runSingle(basePath, target, username, password, insecure, dryRun, prune, timeout)
}

// runDelete executes delete against targets
func runDelete(basePath, target, invFile, group, username, password string, insecure, dryRun bool, timeout time.Duration) error {
	if invFile != "" {
		return runDeleteWithInventory(basePath, invFile, group, username, password, insecure, dryRun, timeout)
	}

	if target == "" {
		return fmt.Errorf("either --target or --inventory required")
	}

	return runDeleteSingle(basePath, target, username, password, insecure, dryRun, timeout)
}

// runWithInventory runs operation against inventory hosts
func runWithInventory(basePath, invFile, group, username, password string, insecure, dryRun, prune bool, timeout time.Duration) error {
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

		if err := runSingle(configPath, target, hostUser, hostPass, hostInsecure, dryRun, prune, timeout); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}

	return nil
}

// runDeleteWithInventory runs delete against inventory hosts
func runDeleteWithInventory(basePath, invFile, group, username, password string, insecure, dryRun bool, timeout time.Duration) error {
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

		if err := runDeleteSingle(configPath, target, hostUser, hostPass, hostInsecure, dryRun, timeout); err != nil {
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

// findHostConfig finds the config path for a host
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

// runSingle runs sync against a single target
func runSingle(configPath, target, username, password string, insecure, dryRun, prune bool, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	app, err := applier.New(applier.Config{
		Target:   target,
		Username: username,
		Password: password,
		Insecure: insecure,
		DryRun:   dryRun,
		Prune:    prune,
	})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer app.Close()

	info, err := os.Stat(configPath)
	if err != nil {
		return err
	}

	if info.IsDir() {
		return app.SyncDir(ctx, configPath)
	}
	return app.SyncFile(ctx, configPath)
}

// runDeleteSingle runs delete against a single target
func runDeleteSingle(configPath, target, username, password string, insecure, dryRun bool, timeout time.Duration) error {
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

	if info.IsDir() {
		return app.ApplyDir(ctx, configPath, applier.OpDelete)
	}
	return app.ApplyFile(ctx, configPath, applier.OpDelete)
}
