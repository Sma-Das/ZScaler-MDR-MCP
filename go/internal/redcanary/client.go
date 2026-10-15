// Package redcanary implements Zscaler MDR / Red Canary REST API v3 reads.
package redcanary

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sma-Das/ZScaler-MDR-MCP/go/internal/mdr"
)

const MaxResponseBytes = 2 << 20
const maxEntries = 200

var tenant = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.my\.redcanary\.co$`)
var alertID = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9]{0,20}-)?([1-9][0-9]{0,14})$`)

func NormalizeBase(raw string) (string, error) {
	u, e := url.Parse(strings.TrimSpace(raw))
	if e != nil || u == nil || u.Scheme != "https" || !tenant.MatchString(u.Hostname()) || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Port() != "" && u.Port() != "443") {
		return "", fmt.Errorf("MDR_BASE_URL must be an HTTPS tenant origin at <tenant>.my.redcanary.co")
	}
	return "https://" + u.Hostname(), nil
}

func NormalizeID(raw string) (string, error) {
	s := strings.TrimPrefix(strings.TrimSpace(raw), "redcanary:")
	m := alertID.FindStringSubmatch(s)
	if m == nil {
		return "", fmt.Errorf("alert_id must be a positive numeric or MDR human alert ID")
	}
	return m[1], nil
}

// Budget is shared across callers: the provider's published limit is per IP.
// Reject excess work instead of sleeping or silently replaying requests.
type Budget struct {
	mu       sync.Mutex
	requests []time.Time
}

func (b *Budget) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	keep := b.requests[:0]
	burst := 0
	for _, t := range b.requests {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
			if now.Sub(t) < time.Second {
				burst++
			}
		}
	}
	b.requests = keep
	if len(keep) >= 20 || burst >= 10 {
		return false
	}
	b.requests = append(b.requests, now)
	return true
}

var upstreamHTTP = func() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxConnsPerHost = 4
	t.MaxIdleConnsPerHost = 4
	t.MaxResponseHeaderBytes = 32 << 10
	t.ResponseHeaderTimeout = 15 * time.Second
	return &http.Client{Timeout: 15 * time.Second, Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}()

func ValidateKey(key string) error {
	if strings.TrimSpace(key) != key || key == "" || len(key) > 1024 || strings.ContainsAny(key, "\r\n,") {
		return fmt.Errorf("provide one bounded MDR API key")
	}
	return nil
}

type Client struct {
	base, key string
	http      *http.Client
	budget    *Budget
}

func New(base, key string, budget *Budget) (*Client, error) {
	normal, e := NormalizeBase(base)
	if e != nil {
		return nil, e
	}
	if e := ValidateKey(key); e != nil {
		return nil, e
	}
	return &Client{normal, key, upstreamHTTP, budget}, nil
}

type envelope struct {
	Data  []map[string]any `json:"data"`
	Links map[string]any   `json:"links"`
}

func (c *Client) read(ctx context.Context, path string) (envelope, error) {
	var out envelope
	if c.budget != nil && !c.budget.allow() {
		return out, fmt.Errorf("MDR request budget reached; retry later (20/minute, no automatic retry)")
	}
	r, e := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/openapi/v3/"+path, nil)
	if e != nil {
		return out, fmt.Errorf("invalid MDR request")
	}
	r.Header.Set("X-API-Key", c.key)
	r.Header.Set("Accept", "application/json")
	r.Header.Set("User-Agent", "ZScaler-MDR-MCP")
	resp, e := c.http.Do(r)
	if e != nil {
		return out, fmt.Errorf("MDR upstream request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return out, fmt.Errorf("MDR upstream returned HTTP %d; response body omitted", resp.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if e != nil || len(b) > MaxResponseBytes {
		return out, fmt.Errorf("MDR response exceeded the read limit or failed")
	}
	// Decode before redaction so JSON escape sequences cannot hide a credential.
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	if decoder.Decode(&out) != nil || out.Data == nil {
		return out, fmt.Errorf("MDR returned an invalid data envelope")
	}
	for _, item := range out.Data {
		redact(item, c.key)
	}
	return out, nil
}

func redact(value any, key string) {
	switch v := value.(type) {
	case map[string]any:
		for k, item := range v {
			if s, ok := item.(string); ok {
				v[k] = strings.ReplaceAll(s, key, "[REDACTED]")
			} else {
				redact(item, key)
			}
		}
	case []any:
		for i, item := range v {
			if s, ok := item.(string); ok {
				v[i] = strings.ReplaceAll(s, key, "[REDACTED]")
			} else {
				redact(item, key)
			}
		}
	}
}

func text(v any) string {
	s, _ := v.(string)
	if len(s) > 16000 {
		s = s[:16000] + " [truncated]"
	}
	return s
}
func object(v any) map[string]any { m, _ := v.(map[string]any); return m }
func id(v any) string {
	switch n := v.(type) {
	case string:
		return n
	case json.Number:
		if _, e := strconv.ParseUint(string(n), 10, 64); e == nil {
			return string(n)
		}
	}
	return ""
}
func notes(v any) []string {
	out := []string{}
	if a, ok := v.([]any); ok {
		for _, x := range a {
			if s := text(x); s != "" {
				out = append(out, s)
			}
			if len(out) >= 20 {
				break
			}
		}
	}
	return out
}

func (c *Client) alert(item map[string]any) mdr.Alert {
	a := object(item["attributes"])
	n := id(item["id"])
	return mdr.Alert{ID: n, Provider: "zscaler-mdr", Title: text(a["headline"]), Summary: text(a["summary"]), Severity: text(a["severity"]), OccurredAt: text(a["time_of_occurrence"]), ConfirmedAt: text(a["confirmed_at"]), UpdatedAt: text(a["updated_at"]), Identity: text(item["username"]), Hostname: text(item["hostname"]), URL: c.base + "/threats/" + n}
}

func (c *Client) List(ctx context.Context, page, limit int) (mdr.Result, error) {
	if page < 1 || page > 20 || limit < 1 || limit > 50 {
		return mdr.Result{}, fmt.Errorf("page must be 1-20 and limit 1-50")
	}
	path := fmt.Sprintf("detections?page=%d&per_page=%d&direction=desc", page, limit)
	out := mdr.NewResult("zscaler-mdr", c.base+"/openapi/v3/"+path)
	p, e := c.read(ctx, path)
	if e != nil {
		return out, e
	}
	for i, x := range p.Data {
		if i >= limit {
			out.Partial = true
			out.Warnings = append(out.Warnings, "Upstream exceeded requested limit")
			break
		}
		out.Alerts = append(out.Alerts, c.alert(x))
	}
	if p.Links["next"] != nil {
		if page == 20 {
			out.Partial = true
			out.Warnings = append(out.Warnings, "Alert page ceiling reached")
		} else {
			out.NextPage = page + 1
		}
	}
	return out, nil
}

func (c *Client) Get(ctx context.Context, raw string) (mdr.Result, error) {
	n, e := NormalizeID(raw)
	if e != nil {
		return mdr.Result{}, e
	}
	path := "detections/" + n
	out := mdr.NewResult("zscaler-mdr", c.base+"/openapi/v3/"+path)
	p, e := c.read(ctx, path)
	if e != nil {
		return out, e
	}
	if len(p.Data) != 1 || id(p.Data[0]["id"]) != n {
		return out, fmt.Errorf("MDR returned an unexpected alert identity")
	}
	out.Alerts = []mdr.Alert{c.alert(p.Data[0])}
	return out, nil
}

func (c *Client) Timeline(ctx context.Context, raw string, maxPages int) (mdr.Result, error) {
	n, e := NormalizeID(raw)
	if e != nil {
		return mdr.Result{}, e
	}
	if maxPages < 1 || maxPages > 3 {
		return mdr.Result{}, fmt.Errorf("max_pages must be 1-3")
	}
	path := "detections/" + n + "/timeline"
	out := mdr.NewResult("zscaler-mdr", c.base+"/openapi/v3/"+path)
	out.Entries = []mdr.Entry{}
	seen := map[[32]byte]bool{}
	for page := 1; page <= maxPages; page++ {
		p, e := c.read(ctx, path+"?page="+strconv.Itoa(page))
		if e != nil {
			if page == 1 {
				return out, e
			}
			out.Partial = true
			out.Warnings = append(out.Warnings, e.Error())
			return out, nil
		}
		added := 0
		for _, x := range p.Data {
			entry := project(x)
			b, _ := json.Marshal(entry)
			fingerprint := sha256.Sum256(b)
			if seen[fingerprint] {
				continue
			}
			seen[fingerprint] = true
			added++
			if len(out.Entries) >= maxEntries {
				out.Partial = true
				out.Warnings = append(out.Warnings, "Timeline entry ceiling reached")
				return out, nil
			}
			out.Entries = append(out.Entries, entry)
		}
		if p.Links["next"] == nil {
			return out, nil
		}
		if added == 0 {
			out.Partial = true
			out.Warnings = append(out.Warnings, "Upstream repeated a timeline page; stopped without assuming completeness")
			return out, nil
		}
		if page == maxPages {
			out.Partial = true
			out.NextPage = page + 1
			out.Warnings = append(out.Warnings, "Timeline page ceiling reached")
		}
	}
	return out, nil
}

func project(x map[string]any) mdr.Entry {
	a := object(x["attributes"])
	r := object(a["response"])
	kind := text(x["type"])
	out := mdr.Entry{ID: id(x["id"]), Type: kind, OccurredAt: text(a["occurred_at"]), Notes: []string{}, Generated: kind == "activity_timelines.ThreatRecommendationsAgentExecution"}
	switch kind {
	case "activity_timelines.EventActivityOccurred", "activity_timelines.ThreatRecommendationsAgentExecution", "activity_timelines.LatestIndicationSeen", "activity_timelines.ThreatDetected", "activity_timelines.AnalystConfirmed":
		out.Notes = notes(a["analyst_notes"])
	default:
		return out
	}
	if out.OccurredAt == "" {
		out.OccurredAt = text(x["created_at"])
	}
	// Never copy response.meta: it can include hidden model reasoning/tool inputs.
	if out.Generated {
		out.Summary = text(r["summary"])
		out.Recommendations = text(r["recommendations"])
	}
	act := object(a["activity"])
	if act != nil {
		out.Activity = map[string]any{}
		for _, k := range []string{"event", "human_summary", "activity_at_ts", "event_type_cd", "succeeded"} {
			switch v := act[k].(type) {
			case string:
				out.Activity[k] = text(v)
			case bool:
				out.Activity[k] = v
			}
		}
		ip := object(object(act["source_network_address"])["ip"])
		if v := text(ip["ip_address"]); v != "" {
			out.Activity["source_ip"] = v
		}
	}
	// In particular do not copy playbooks/actions/secure_data/native_event, even
	// when they appear in unexpected locations. Unknown kinds retain metadata only.
	return out
}
