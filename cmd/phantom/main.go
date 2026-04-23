package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"text/tabwriter"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"phantom/fingerprints"
	"phantom/proxy"
	"phantom/tui"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var (
		addr        string
		profileID   string
		profileFile string
		verbose     bool
		dashboard   bool
	)

	root := &cobra.Command{
		Use:   "phantom",
		Short: "TLS fingerprint impersonation proxy",
		Long: `Phantom is a local MITM proxy that spoofs TLS ClientHello fingerprints.

Outbound HTTPS connections are made to look like they come from a specific
browser or device — useful for studying how anti-bot systems like Cloudflare,
Akamai, and DataDome respond to different JA3/JA4 hashes.

Before using, add ~/.phantom/ca.crt to your OS trust store so your browser
doesn't complain about the MITM certificate.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(addr, profileID, profileFile, verbose, dashboard)
		},
	}

	root.Flags().StringVarP(&addr, "addr", "a", "127.0.0.1:8080", "listen address")
	root.Flags().StringVarP(&profileID, "profile", "p", "chrome_120", "built-in profile to use")
	root.Flags().StringVarP(&profileFile, "profile-file", "f", "", "load profile from a JSON file instead of a built-in")
	root.Flags().BoolVarP(&verbose, "verbose", "v", false, "log extra detail per connection")
	root.Flags().BoolVarP(&dashboard, "dashboard", "d", false, "show live connection dashboard (TUI)")

	root.AddCommand(profilesCmd())

	return root
}

func run(addr, profileID, profileFile string, verbose, dashboard bool) error {
	var (
		profile *fingerprints.Profile
		err     error
	)

	if profileFile != "" {
		profile, err = fingerprints.LoadFromFile(profileFile)
	} else {
		profile, err = fingerprints.Get(profileID)
	}
	if err != nil {
		return fmt.Errorf("loading profile: %w", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("finding home dir: %w", err)
	}
	caDir := filepath.Join(home, ".phantom")

	ca, err := proxy.LoadOrCreateCA(caDir)
	if err != nil {
		return fmt.Errorf("setting up CA: %w", err)
	}

	events := make(chan proxy.ConnEvent, 256)

	p := &proxy.Proxy{
		CA:      ca,
		Profile: profile,
		Verbose: verbose,
		Events:  events,
	}

	if dashboard {
		// Silence the log output so it doesn't clobber the TUI.
		log.SetOutput(io.Discard)

		go func() {
			if err := p.ListenAndServe(addr); err != nil {
				// Can't log — output is discarded. The TUI will just stop
				// receiving new events if the server dies.
				_ = err
			}
		}()

		m := tui.New(events, profile.Name, addr)
		prog := tea.NewProgram(m, tea.WithAltScreen())
		if _, err := prog.Run(); err != nil {
			return fmt.Errorf("dashboard: %w", err)
		}
		return nil
	}

	// Plain mode: print CA path and start the server with log output.
	caPath := filepath.Join(caDir, "ca.crt")
	fmt.Printf("CA cert: %s\n", caPath)
	fmt.Printf("Add it to your OS trust store to avoid certificate warnings.\n\n")

	// Drain events in the background so the channel never fills.
	go func() {
		for range events {
		}
	}()

	return p.ListenAndServe(addr)
}

func profilesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "profiles",
		Short: "List available built-in fingerprint profiles",
		Run: func(cmd *cobra.Command, args []string) {
			all := fingerprints.List()
			sort.Slice(all, func(i, j int) bool {
				return all[i].ID < all[j].ID
			})

			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tDESCRIPTION")
			for _, p := range all {
				fmt.Fprintf(tw, "%s\t%s\t%s\n", p.ID, p.Name, p.Description)
			}
			tw.Flush()
		},
	}
}
