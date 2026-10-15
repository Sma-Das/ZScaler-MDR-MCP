// Package mdr defines the provider-neutral, read-only investigation contract.
package mdr

import (
	"context"
	"time"
)

type Alert struct {
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	Title       string `json:"title"`
	Summary     string `json:"summary"`
	Severity    string `json:"severity"`
	OccurredAt  string `json:"occurred_at,omitempty"`
	ConfirmedAt string `json:"confirmed_at,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
	Identity    string `json:"identity,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	URL         string `json:"url"`
}

type Entry struct {
	ID              string         `json:"id,omitempty"`
	Type            string         `json:"type"`
	OccurredAt      string         `json:"occurred_at,omitempty"`
	Notes           []string       `json:"analyst_notes"`
	Summary         string         `json:"summary,omitempty"`
	Recommendations string         `json:"recommendations,omitempty"`
	Activity        map[string]any `json:"activity,omitempty"`
	Generated       bool           `json:"generated"`
}

type Result struct {
	Provider    string   `json:"provider"`
	Source      string   `json:"source"`
	RetrievedAt string   `json:"retrieved_at"`
	Alerts      []Alert  `json:"alerts,omitempty"`
	Entries     []Entry  `json:"entries,omitempty"`
	Partial     bool     `json:"partial"`
	Warnings    []string `json:"warnings"`
	NextPage    int      `json:"next_page,omitempty"`
}

func NewResult(provider, source string) Result {
	return Result{Provider: provider, Source: source, RetrievedAt: time.Now().UTC().Format(time.RFC3339Nano), Warnings: []string{}}
}

// Provider implementations must fix upstream origins at startup, expose reads
// only, and return projected evidence rather than arbitrary upstream objects.
type Provider interface {
	List(context.Context, int, int) (Result, error)
	Get(context.Context, string) (Result, error)
	Timeline(context.Context, string, int) (Result, error)
}
