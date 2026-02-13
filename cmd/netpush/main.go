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

	rootCmd.AddCommand(syncCmd())
	rootCmd.AddCommand(applyCmd())
	rootCmd.AddCommand(deleteCmd())
	rootCmd.AddCommand(diffCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
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
		Short: "Sync config - diff and apply minimal changes",
		Long: `Sync network configuration by comparing local YAML to device state.

Computes the minimal set of changes needed:
- Adds config that exists in YAML but not on device
- Updates config that differs between YAML and device  
- Deletes config that exists on device but not in YAML

This is the safest way to ensure device matches your YAML.

Examples:
  # Sync single device
  netpush sync ./host_vars/leaf1/ -t leaf1:6030 -u admin -P admin -k

  # Sync using inventory
  netpush sync ./ -i inventory.yaml

  # Sync specific group
  netpush sync ./ -i inventory.yaml --group leaf

  # Dry run - preview changes
  netpush sync ./ -i inventory.yaml --dry-run`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			basePath := args[0]

			if inventoryFile != "" {
				return runWithInventory(basePath, inventoryFile, group, username, password, insecure, dryRun, timeout, "sync")
			}

			if target == "" {
				return fmt.Errorf("either --target or --inventory required")
			}

			return runSingle(basePath, target, username, password, insecure, dryRun, timeout, "sync")
		},
	}

	cmd.Flags().StringVarP(&target, "target", "t", "", "target device (host:port)")
	cmd.Flags().StringVarP(&inventoryFile, "inventory", "i", "", "inventory file")
	cmd.Flags().StringVarP(&group, "group", "g", "", "target group from inventory")
	cmd.Flags().StringVarP(&username, "username", "u", "", "gNMI username")
	cmd.Flags().StringVarP(&password, "password", "P", "", "gNMI password")
	cmd.Flags().BoolVarP(&insecure, "insecure", "k", false, "skip TLS verification")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would change without applying")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "operation timeout")

	return cmd
}

func applyCmd() *cobra.Command {
	var (
		target        string
		inventoryFile string
		group         string
		username      string
		password      string
		insecure      bool
		replace       bool
		dryRun        bool
		timeout       time.Duration
	)

	cmd := &cobra.Command{
		Use:   "apply <path>",
		Short: "Apply config (merge with existing)",
		Long: `Apply network configuration via gNMI Set operations.

Uses merge semantics - adds/updates config without removing existing.
For declarative sync with deletions, use 'sync' instead.

Examples:
  # Apply to single device
  netpush apply ./host_vars/leaf1/ -t leaf1:6030 -u admin -P admin -k

  # Apply using inventory  
  netpush apply ./ -i inventory.yaml

  # Apply with replace (full subtree replace)
  netpush apply ./ -i inventory.yaml --replace`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			basePath := args[0]
			op := "apply"
			if replace {
				op = "replace"
			}

			if inventoryFile != "" {
				return runWithInventory(basePath, inventoryFile, group, username, password, insecure, dryRun, timeout, op)
			}

			if target == "" {
				return fmt.Errorf("either --target or --inventory required")
			}

			return runSingle(basePath, target, username, password, insecure, dryRun, timeout, op)
		},
	}

	cmd.Flags().StringVarP(&target, "target", "t", "", "target device (host:port)")
	cmd.Flags().StringVarP(&inventoryFile, "inventory", "i", "", "inventory file")
	cmd.Flags().StringVarP(&group, "group", "g", "", "target group from inventory")
	cmd.Flags().StringVarP(&username, "username", "u", "", "gNMI username")
	cmd.Flags().StringVarP(&password, "password", "P", "", "gNMI password")
	cmd.Flags().BoolVarP(&insecure, "insecure", "k", false, "skip TLS verification")
	cmd.Flags().BoolVar(&replace, "replace", false, "replace instead of merge")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be applied without applying")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "operation timeout")

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
		Long: `Delete network configuration via gNMI Set delete operations.

Examples:
  # Delete from single device
  netpush delete ./remove-peer.yaml -t leaf1:6030 -u admin -P admin -k

  # Delete using inventory
  netpush delete ./remove-peer.yaml -i inventory.yaml --group leaf`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			basePath := args[0]

			if inventoryFile != "" {
				return runWithInventory(basePath, inventoryFile, group, username, password, insecure, dryRun, timeout, "delete")
			}

			if target == "" {
				return fmt.Errorf("either --target or --inventory required")
			}

			return runSingle(basePath, target, username, password, insecure, dryRun, timeout, "delete")
		},
	}

	cmd.Flags().StringVarP(&target, "target", "t", "", "target device (host:port)")
	cmd.Flags().StringVarP(&inventoryFile, "inventory", "i", "", "inventory file")
	cmd.Flags().StringVarP(&group, "group", "g", "", "target group from inventory")
	cmd.Flags().StringVarP(&username, "username", "u", "", "gNMI username")
	cmd.Flags().StringVarP(&password, "password", "P", "", "gNMI password")
	cmd.Flags().BoolVarP(&insecure, "insecure", "k", false, "skip TLS verification")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be deleted without deleting")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "operation timeout")

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
		Short: "Show diff between YAML and device config",
		Long: `Compare local YAML config with device's current config.

Shows what would change if you ran 'sync'.

Examples:
  netpush diff ./host_vars/leaf1/ -t leaf1:6030 -u admin -P admin -k
  netpush diff ./ -i inventory.yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			basePath := args[0]

			if inventoryFile != "" {
				return runWithInventory(basePath, inventoryFile, group, username, password, insecure, true, timeout, "diff")
			}

			if target == "" {
				return fmt.Errorf("either --target or --inventory required")
			}

			return runSingle(basePath, target, username, password, insecure, true, timeout, "diff")
		},
	}

	cmd.Flags().StringVarP(&target, "target", "t", "", "target device (host:port)")
	cmd.Flags().StringVarP(&inventoryFile, "inventory", "i", "", "inventory file")
	cmd.Flags().StringVarP(&group, "group", "g", "", "target group from inventory")
	cmd.Flags().StringVarP(&username, "username", "u", "", "gNMI username")
	cmd.Flags().StringVarP(&password, "password", "P", "", "gNMI password")
	cmd.Flags().BoolVarP(&insecure, "insecure", "k", false, "skip TLS verification")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "operation timeout")

	return cmd
}

// runWithInventory runs operation against inventory hosts
func runWithInventory(basePath, invFile, group, username, password string, insecure, dryRun bool, timeout time.Duration, op string) error {
	inv, err := inventory.Load(invFile)
	if err != nil {
		return fmt.Errorf("load inventory: %w", err)
	}

	// Get target hosts
	var hosts []string
	if group != "" {
		var ok bool
		hosts, ok = inv.GetGroup(group)
		if !ok {
			return fmt.Errorf("group %q not found", group)
		}
	} else {
		hosts, _ = inv.GetGroup("all")
	}

	if len(hosts) == 0 {
		return fmt.Errorf("no hosts found")
	}

	// Process each host
	for _, host := range hosts {
		target := inv.ResolveHost(host)
		hostUser, hostPass, hostInsecure := inv.GetHostCredentials(host)

		// CLI flags override inventory
		if username != "" {
			hostUser = username
		}
		if password != "" {
			hostPass = password
		}
		if insecure {
			hostInsecure = true
		}

		// Determine config path for this host
		configPath := findHostConfig(basePath, host)

		fmt.Printf("\n=== %s (%s) ===\n", host, target)

		if err := runSingle(configPath, target, hostUser, hostPass, hostInsecure, dryRun, timeout, op); err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}
	}

	return nil
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

	// Fallback to base path
	return basePath
}

// runSingle runs operation against a single target
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
	case "sync", "diff":
		if info.IsDir() {
			return app.SyncDir(ctx, configPath)
		}
		return app.SyncFile(ctx, configPath)

	case "apply":
		if info.IsDir() {
			return app.ApplyDir(ctx, configPath, applier.OpUpdate)
		}
		return app.ApplyFile(ctx, configPath, applier.OpUpdate)

	case "replace":
		if info.IsDir() {
			return app.ApplyDir(ctx, configPath, applier.OpReplace)
		}
		return app.ApplyFile(ctx, configPath, applier.OpReplace)

	case "delete":
		if info.IsDir() {
			return app.ApplyDir(ctx, configPath, applier.OpDelete)
		}
		return app.ApplyFile(ctx, configPath, applier.OpDelete)
	}

	return fmt.Errorf("unknown operation: %s", op)
}
