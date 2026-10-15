package redcanary

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	c, e := New("https://example.my.redcanary.co", "synthetic-api-key", nil)
	if e != nil {
		t.Fatal(e)
	}
	c.base = s.URL
	return c
}

func TestTenantAndIDValidation(t *testing.T) {
	for _, raw := range []string{"http://example.my.redcanary.co", "https://evil.example", "https://example.my.redcanary.co.evil.example", "https://u:p@example.my.redcanary.co", "https://example.my.redcanary.co/path", "https://example.my.redcanary.co?token=a", "https://example.my.redcanary.co:8443"} {
		if _, e := NormalizeBase(raw); e == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	for _, raw := range []string{"123", "THREAT-123", "DEMO-123", "redcanary:123"} {
		if n, e := NormalizeID(raw); e != nil || n != "123" {
			t.Errorf("unexpected normalization for %q", raw)
		}
	}
	for _, raw := range []string{"../123", "123?url=x", "0", "123/notes", "https://evil.example/123"} {
		if _, e := NormalizeID(raw); e == nil {
			t.Errorf("accepted %q", raw)
		}
	}
}

func TestTimelineProjectionDedupAndSecrets(t *testing.T) {
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.Header.Get("X-API-Key") != "synthetic-api-key" {
			t.Error("unexpected method or authentication")
		}
		_, _ = w.Write([]byte(`{"links":{"next":"https://evil.example/steal"},"data":[{"type":"activity_timelines.EventActivityOccurred","attributes":{"occurred_at":"2026-01-01T01:00:00Z","analyst_notes":["An investigated logon; synthetic-api-key must be redacted"],"activity":{"succeeded":true,"human_summary":"Synthetic logon","native_event":{"password":"native-secret"}}}},{"type":"activity_timelines.ThreatRecommendationsAgentExecution","attributes":{"response":{"summary":"Generated summary","recommendations":"Review this activity","meta":{"reasoning":"hidden-reasoning"}}}},{"type":"exec.PlaybookExecution","id":42,"secure_data":{"httpHeaders":"Authorization=Bearer webhook-secret"},"playbook":{"password":"nested-secret"}}]}`))
	})
	r, e := c.Timeline(context.Background(), "DEMO-123", 3)
	if e != nil {
		t.Fatal(e)
	}
	if calls != 2 || len(r.Entries) != 3 || !r.Partial || !strings.Contains(strings.Join(r.Warnings, " "), "repeated") {
		t.Fatalf("lost pagination state: calls %d result %#v", calls, r)
	}
	b, _ := json.Marshal(r)
	for _, secret := range []string{"synthetic-api-key", "native-secret", "hidden-reasoning", "webhook-secret", "nested-secret", "secure_data", "native_event"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("leaked %s", secret)
		}
	}
	if !r.Entries[1].Generated || r.Entries[1].Recommendations == "" {
		t.Error("lost generated recommendations")
	}
}

func TestTimelinePreservesPartialFailure(t *testing.T) {
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 2 {
			http.Error(w, "secret-error-body", 429)
			return
		}
		_, _ = w.Write([]byte(`{"links":{"next":"ignored"},"data":[{"type":"activity_timelines.EventActivityOccurred","attributes":{"analyst_notes":["preserve me"]}}]}`))
	})
	r, e := c.Timeline(context.Background(), "123", 3)
	if e != nil || !r.Partial || len(r.Entries) != 1 {
		t.Fatalf("partial result lost: %v %#v", e, r)
	}
	if strings.Contains(strings.Join(r.Warnings, " "), "secret-error-body") {
		t.Fatal("upstream body leaked")
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	hit := false
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer destination.Close()
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 302) })
	if _, e := c.Get(context.Background(), "123"); e == nil || hit {
		t.Fatal("redirect followed or not reported")
	}
}

func TestIdentityAndResponseBounds(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":456,"attributes":{}}]}`))
	})
	if _, e := c.Get(context.Background(), "123"); e == nil {
		t.Fatal("identity mismatch accepted")
	}
	c = testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", MaxResponseBytes+1)))
	})
	if _, e := c.Get(context.Background(), "123"); e == nil {
		t.Fatal("oversized response accepted")
	}
}

func TestBudgetBounds(t *testing.T) {
	b := &Budget{}
	for i := 0; i < 10; i++ {
		if !b.allow() {
			t.Fatal("unexpected rejection")
		}
	}
	if b.allow() {
		t.Fatal("burst budget not enforced")
	}
}

func TestDecodedSecretRedactionAndUnknownKinds(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"type":"activity_timelines.EventActivityOccurred","attributes":{"analyst_notes":["synthetic-\u0061pi-key"]}},{"type":"exec.PlaybookExecution","attributes":{"analyst_notes":["automation-secret"],"response":{"summary":"automation-secret","recommendations":"automation-secret"},"activity":{"event":"automation-secret"}}}]}`))
	})
	r, e := c.Timeline(context.Background(), "123", 1)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(r)
	for _, secret := range []string{"synthetic-api-key", "automation-secret"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("secret leaked")
		}
	}
}

func TestFractionalIDCannotMatch(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":123.4,"attributes":{}}]}`))
	})
	if _, e := c.Get(context.Background(), "123"); e == nil {
		t.Fatal("fractional ID matched")
	}
}

func TestListPageCeiling(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[],"links":{"next":"ignored"}}`))
	})
	r, e := c.List(context.Background(), 20, 10)
	if e != nil || !r.Partial || r.NextPage != 0 {
		t.Fatalf("unsupported pagination: %#v %v", r, e)
	}
}
