package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/spf13/cobra"

	"ssh-inspect/internal/ssh"
)

// completeHostnames returns SSH hostnames from the user's config and
// known_hosts files for shell completion.
func completeHostnames(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	sshDir := filepath.Join(home, ".ssh")
	seen := make(map[string]bool)

	// Collect hostnames from SSH config.
	if configContent, err := ssh.ReadConfig(filepath.Join(sshDir, "config"), sshDir); err == nil {
		for _, h := range ssh.ParseHostnames(configContent) {
			seen[h] = true
		}
	}

	// Collect hostnames from known_hosts files.
	knownHostsPaths := []string{
		filepath.Join(sshDir, "known_hosts"),
	}
	// Also check known_hosts.d directory for additional files.
	if matches, err := filepath.Glob(filepath.Join(sshDir, "known_hosts.d", "*")); err == nil {
		knownHostsPaths = append(knownHostsPaths, matches...)
	}
	for _, path := range knownHostsPaths {
		if data, err := os.ReadFile(path); err == nil {
			for _, h := range ssh.ParseKnownHostnames(string(data)) {
				seen[h] = true
			}
		}
	}

	if len(seen) == 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	slices.Sort(hosts)
	return hosts, cobra.ShellCompDirectiveNoFileComp
}

func run(cmd *cobra.Command, args []string) error {
	target := args[0]

	withWildcard, wildcardConfig, err := ssh.Baselines()
	if err != nil {
		return err
	}

	// Resolve chain using withWildcard as baseline so entries contain
	// only host-specific settings (Host * already accounted for).
	chain, err := ssh.ResolveChain(target, withWildcard, make(map[string]bool))
	if err != nil {
		return err
	}

	color := ssh.IsTerminal()
	first := true

	// Show wildcard settings first — these apply to all hosts.
	if len(wildcardConfig) > 0 {
		ssh.PrintConfig("*", wildcardConfig, color, true)
		first = false
	}

	// Show host-specific sections (target and any proxies).
	for _, entry := range chain {
		if len(entry.Config) == 0 {
			continue
		}
		if !first {
			fmt.Println()
		}
		first = false
		ssh.PrintConfig(entry.Name, entry.Config, color, false)
	}

	return nil
}

// Execute runs the root command.
func Execute() {
	rootCmd := &cobra.Command{
		Use:   "ssh-inspect <hostname>",
		Short: "Show SSH configuration for a hostname",
		Long: `Shows SSH configuration applying to a hostname,
including Host * and Match all settings, excluding SSH built-in defaults.`,
		Args:              cobra.ExactArgs(1),
		RunE:              run,
		ValidArgsFunction: completeHostnames,
		SilenceUsage:      true,
	}

	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
