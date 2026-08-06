// Package tui is an optional viewer over a completed verdict.Report.
//
// Deliberately a VIEWER, not the product. canary is headless first: it must
// run in CI and cron and be branched on by exit code. The TUI opens an
// existing report and lets you navigate it; it never drives a scan.
//
// This is the one lesson taken from spark as a warning rather than a pattern:
// spark is TUI-first, and 7,104 of its 19,761 lines are interface, which is
// what makes it awkward to run unattended. See docs/RESEARCH/SPARK_ANALYSIS.md.
//
// Planned stack: charmbracelet/bubbletea (v1 stable — v2 is still RC) with
// bubbles and lipgloss. Bubble Tea's Elm architecture fits: the model IS the
// report, Update only moves the cursor, View only renders.
//
// STATUS: not implemented.
package tui

import "github.com/dPeluChe/canary/internal/verdict"

// Run opens an interactive viewer over a finished report.
func Run(r *verdict.Report) error {
	panic("not implemented")
}
