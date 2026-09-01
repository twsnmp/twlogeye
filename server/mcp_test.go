package server

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
)

func TestMCPResourcesAndEmptyTools(t *testing.T) {
	ctx := context.Background()
	datastore.Config.SigmaRules = "embed:test"
	auditor.Init()

	s := NewMCPServer("v0.6.0")
	c := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "v0.0.1"}, nil)

	t1, t2 := mcp.NewInMemoryTransports()
	go func() {
		if _, err := s.Connect(ctx, t1, nil); err != nil {
			t.Logf("server connect err: %v", err)
		}
	}()
	cs, err := c.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("client connect err: %v", err)
	}
	defer cs.Close()

	// List resources
	resList := []string{}
	for r, err := range cs.Resources(ctx, nil) {
		if err != nil {
			t.Fatalf("list resources err: %v", err)
		}
		resList = append(resList, r.URI)
	}
	t.Logf("found %d resources: %v", len(resList), resList)

	// Test read resource
	for _, uri := range resList {
		res, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
		if err != nil {
			t.Errorf("read resource %s err: %v", uri, err)
			continue
		}
		if len(res.Contents) == 0 {
			t.Errorf("resource %s has no contents", uri)
		}
	}

	// Test call tools with empty arguments {}
	toolsToTestEmpty := []string{
		"get_report",
		"get_last_report",
		"get_anomaly_report",
		"search_log",
		"search_notify",
		"get_sigma_evaluator_list",
		"get_sigma_rule_id_list",
		"reload_sigma_rule",
	}

	for _, toolName := range toolsToTestEmpty {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{
			Name:      toolName,
			Arguments: map[string]any{},
		})
		if err != nil {
			t.Errorf("CallTool %s with empty arguments failed: %v", toolName, err)
		} else {
			t.Logf("CallTool %s success, isError=%v", toolName, res.IsError)
		}
	}

	// Test get_sigma_rule with an embedded rule ID
	ruleRes, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_sigma_rule",
		Arguments: map[string]any{
			"id": "df53630a-5c64-4a8c-827c-190fb77738e1",
		},
	})
	if err != nil {
		t.Fatalf("CallTool get_sigma_rule failed: %v", err)
	}
	if ruleRes.IsError {
		t.Fatalf("CallTool get_sigma_rule returned error result")
	}
	if len(ruleRes.Content) == 0 {
		t.Fatalf("CallTool get_sigma_rule returned no content")
	}
	t.Logf("get_sigma_rule content: %s", ruleRes.Content[0].(*mcp.TextContent).Text)
}
