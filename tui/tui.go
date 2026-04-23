package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"phantom/proxy"
)

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("51"))
	subtitleStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	labelStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	valueStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("51"))
	boldStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("255"))
	dimStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	hostStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("255"))
	hashStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("38"))
	httpStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	errStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	warnStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	borderStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("237"))
)

type connMsg proxy.ConnEvent

// Model is the bubbletea model for the live connection dashboard.
type Model struct {
	conns   []proxy.ConnEvent
	profile string
	addr    string
	total   int
	width   int
	height  int
	ch      <-chan proxy.ConnEvent
}

// New creates a dashboard model. ch must not be nil.
func New(ch <-chan proxy.ConnEvent, profile, addr string) Model {
	return Model{
		conns:   make([]proxy.ConnEvent, 0, 64),
		profile: profile,
		addr:    addr,
		ch:      ch,
	}
}

func (m Model) Init() tea.Cmd {
	return listenForConn(m.ch)
}

func listenForConn(ch <-chan proxy.ConnEvent) tea.Cmd {
	return func() tea.Msg {
		return connMsg(<-ch)
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

	case connMsg:
		m.total++
		m.conns = append([]proxy.ConnEvent{proxy.ConnEvent(msg)}, m.conns...)
		maxRows := m.height - 10
		if maxRows < 3 {
			maxRows = 3
		}
		if len(m.conns) > maxRows {
			m.conns = m.conns[:maxRows]
		}
		return m, listenForConn(m.ch)
	}

	return m, nil
}

func (m Model) View() string {
	if m.width == 0 {
		return "\n  loading...\n"
	}

	var b strings.Builder

	b.WriteString("\n")
	b.WriteString("  " + titleStyle.Render("PHANTOM") + "  " + subtitleStyle.Render("TLS fingerprint impersonation proxy") + "\n")
	b.WriteString("\n")

	b.WriteString(fmt.Sprintf("  %s %s    %s %s    %s %s\n",
		labelStyle.Render("profile:"), valueStyle.Render(m.profile),
		labelStyle.Render("addr:"), valueStyle.Render(m.addr),
		labelStyle.Render("total:"), boldStyle.Render(fmt.Sprintf("%d", m.total)),
	))
	b.WriteString("\n")

	const (
		timeW = 10
		hostW = 30
		ja3W  = 38
	)

	header := boldStyle.Render(fmt.Sprintf("  %-*s  %-*s  %-*s", timeW, "TIME", hostW, "HOST", ja3W, "STATUS / JA3"))
	b.WriteString(header + "\n")
	b.WriteString(borderStyle.Render("  "+strings.Repeat("─", timeW+hostW+ja3W+6)) + "\n")

	if len(m.conns) == 0 {
		b.WriteString("\n  " + dimStyle.Render("waiting for connections...") + "\n")
	} else {
		for _, c := range m.conns {
			ts := dimStyle.Render(pad(c.Time.Format("15:04:05"), timeW))
			host := hostStyle.Render(pad(trunc(c.Host, hostW), hostW))

			var statusCell string
			switch {
			case c.Err != "":
				// Cert-not-trusted errors get a special warning colour so they stand out.
				if strings.Contains(c.Err, "cert not trusted") {
					statusCell = warnStyle.Render(pad(trunc(c.Err, ja3W), ja3W))
				} else {
					statusCell = errStyle.Render(pad(trunc(c.Err, ja3W), ja3W))
				}
			case c.IsHTTP:
				statusCell = httpStyle.Render(pad("HTTP (no TLS)", ja3W))
			default:
				statusCell = hashStyle.Render(pad(c.JA3, ja3W))
			}

			b.WriteString(fmt.Sprintf("  %s  %s  %s\n", ts, host, statusCell))
		}
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("  press q to quit"))
	b.WriteString("\n")

	return b.String()
}

func trunc(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func pad(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}
