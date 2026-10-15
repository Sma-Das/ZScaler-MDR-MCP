package mcpserver

import (
	"context"
	"testing"

	"github.com/Sma-Das/ZScaler-MDR-MCP/go/internal/mdr"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fakeProvider struct{}

func (fakeProvider) List(context.Context, int, int) (mdr.Result, error) {
	return mdr.NewResult("test", "test"), nil
}
func (fakeProvider) Get(context.Context, string) (mdr.Result, error) {
	return mdr.NewResult("test", "test"), nil
}
func (fakeProvider) Timeline(context.Context, string, int) (mdr.Result, error) {
	return mdr.NewResult("test", "test"), nil
}
func TestReadOnlyToolContract(t *testing.T) {
	ctx := context.Background()
	a, b := mcp.NewInMemoryTransports()
	ss, e := New(fakeProvider{}).Connect(ctx, a, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer ss.Close()
	cs, e := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx, b, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer cs.Close()
	r, e := cs.ListTools(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Tools) != 3 {
		t.Fatalf("unexpected tools %d", len(r.Tools))
	}
	for _, tool := range r.Tools {
		if !tool.Annotations.ReadOnlyHint || *tool.Annotations.DestructiveHint {
			t.Fatal("tool not annotated read-only")
		}
	}
	v, e := cs.CallTool(ctx, &mcp.CallToolParams{Name: "mdr_get_alert_timeline", Arguments: map[string]any{"alert_id": "123"}})
	if e != nil || v.IsError || v.StructuredContent == nil {
		t.Fatalf("MCP result failed: %v %#v", e, v)
	}
	if _, e := cs.CallTool(ctx, &mcp.CallToolParams{Name: "close_alert", Arguments: map[string]any{}}); e == nil {
		t.Fatal("write tool unexpectedly exists")
	}
}
