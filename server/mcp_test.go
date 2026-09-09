package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
)

func TestMCPResourcesAndEmptyTools(t *testing.T) {
	ctx := context.Background()
	datastore.Config.SigmaRules = "embed:test"
	auditor.Init()

	s := NewMCPServer("v0.7.0")
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

func TestMCPSigmaPacks(t *testing.T) {
	ctx := context.Background()
	s := NewMCPServer("v0.7.0")
	c := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "v0.0.1"}, nil)

	t1, t2 := mcp.NewInMemoryTransports()
	go func() {
		_, _ = s.Connect(ctx, t1, nil)
	}()
	cs, err := c.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("client connect err: %v", err)
	}
	defer cs.Close()

	// 1. Test get_sigma_packs without arguments (lists all packs)
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_sigma_packs",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("get_sigma_packs error: %v", err)
	}
	if res.IsError || len(res.Content) == 0 {
		t.Fatalf("get_sigma_packs returned error or no content")
	}
	text := res.Content[0].(*mcp.TextContent).Text
	var packs []*datastore.SigmaPackInfo
	if err := json.Unmarshal([]byte(text), &packs); err != nil {
		t.Fatalf("failed to unmarshal packs: %v, raw=%s", err, text)
	}
	if len(packs) < 7 {
		t.Errorf("expected at least 7 packs, got %d", len(packs))
	}
	foundWin := false
	for _, p := range packs {
		if p.Name == "windows-essential" {
			foundWin = true
			if p.RuleCount == 0 {
				t.Errorf("windows-essential should have > 0 rules")
			}
			if p.Description == "" {
				t.Errorf("windows-essential should have description")
			}
		}
	}
	if !foundWin {
		t.Errorf("windows-essential pack not found in packs list")
	}

	// 2. Test get_sigma_packs for a specific pack
	resSpec, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_sigma_packs",
		Arguments: map[string]any{
			"pack": "linux-auth",
		},
	})
	if err != nil || resSpec.IsError || len(resSpec.Content) == 0 {
		if resSpec != nil && len(resSpec.Content) > 0 {
			t.Fatalf("get_sigma_packs for linux-auth failed: isError=%v, text=%s", resSpec.IsError, resSpec.Content[0].(*mcp.TextContent).Text)
		}
		t.Fatalf("get_sigma_packs for linux-auth failed: err=%v, resSpec=%+v", err, resSpec)
	}
	var singlePack datastore.SigmaPackInfo
	if err := json.Unmarshal([]byte(resSpec.Content[0].(*mcp.TextContent).Text), &singlePack); err != nil {
		t.Fatalf("failed to unmarshal single pack: %v", err)
	}
	if singlePack.Name != "linux-auth" || len(singlePack.Rules) == 0 {
		t.Errorf("invalid single pack result: %+v", singlePack)
	}

	// 3. Test get_sigma_packs for nonexistent pack
	resBad, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_sigma_packs",
		Arguments: map[string]any{
			"pack": "nonexistent-pack",
		},
	})
	if err != nil {
		t.Fatalf("call tool failed: %v", err)
	}
	if !resBad.IsError {
		t.Errorf("expected error for nonexistent pack, got success")
	}

	// 4. Test reading twlogeye://sigma/packs resource
	resRes, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "twlogeye://sigma/packs"})
	if err != nil || len(resRes.Contents) == 0 {
		t.Fatalf("failed to read resource twlogeye://sigma/packs: %v", err)
	}
	if !strings.Contains(resRes.Contents[0].Text, "windows-essential") {
		t.Errorf("twlogeye://sigma/packs does not contain windows-essential")
	}
}

func TestMCPWazuhConversion(t *testing.T) {
	ctx := context.Background()
	datastore.OpenDB()
	defer datastore.CloseDB()
	auditor.Init()

	s := NewMCPServer("v0.7.0")
	c := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "v0.0.1"}, nil)

	t1, t2 := mcp.NewInMemoryTransports()
	go func() {
		_, _ = s.Connect(ctx, t1, nil)
	}()
	cs, err := c.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("client connect err: %v", err)
	}
	defer cs.Close()

	wazuhXML := `<group name="syslog,sshd,">
  <rule id="5700" level="0">
    <match>sshd</match>
    <description>SSHD grouping rule</description>
  </rule>
  <rule id="5710" level="5">
    <if_sid>5700</if_sid>
    <match>illegal user</match>
    <description>Attempt to login using a non-existent user</description>
  </rule>
  <rule id="5712" level="10" frequency="6" timeframe="120">
    <if_matched_sid>5710</if_matched_sid>
    <same_source_ip />
    <description>SSHD brute force trying to get access to the system</description>
  </rule>
</group>`

	// 1. Test convert_wazuh_rules
	convRes, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "convert_wazuh_rules",
		Arguments: map[string]any{
			"xml": wazuhXML,
		},
	})
	if err != nil || convRes.IsError || len(convRes.Content) == 0 {
		t.Fatalf("convert_wazuh_rules failed: %v, content=%v", err, convRes)
	}
	var convResult mcpConvertWazuhResult
	if err := json.Unmarshal([]byte(convRes.Content[0].(*mcp.TextContent).Text), &convResult); err != nil {
		t.Fatalf("failed to unmarshal convert_wazuh_rules result: %v", err)
	}
	if convResult.TotalRules != 3 || convResult.ConvertedCount != 3 {
		t.Fatalf("expected 3 total and 3 converted rules, got %d and %d", convResult.TotalRules, convResult.ConvertedCount)
	}
	// Check correlation on rule 5712
	hasCorr := false
	for _, r := range convResult.Rules {
		if r.ID == "wazuh-5712" && r.HasCorrelation {
			hasCorr = true
			if r.Correlation == nil || r.Correlation.Frequency != 6 {
				t.Errorf("expected frequency 6, got %+v", r.Correlation)
			}
		}
	}
	if !hasCorr {
		t.Errorf("wazuh-5712 rule missing correlation")
	}

	// 2. Test convert_wazuh_decoder
	decoderXML := `<decoder name="sshd">
  <program_name>^sshd</program_name>
</decoder>
<decoder name="sshd-success">
  <parent>sshd</parent>
  <regex offset="after_parent">^Accepted \S+ for (\S+) from (\S+) port </regex>
  <order>user, srcip</order>
</decoder>`

	decRes, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "convert_wazuh_decoder",
		Arguments: map[string]any{
			"xml": decoderXML,
		},
	})
	if err != nil || decRes.IsError || len(decRes.Content) == 0 {
		t.Fatalf("convert_wazuh_decoder failed: %v, content=%v", err, decRes)
	}
	var decResult mcpConvertDecoderResult
	if err := json.Unmarshal([]byte(decRes.Content[0].(*mcp.TextContent).Text), &decResult); err != nil {
		t.Fatalf("failed to unmarshal convert_wazuh_decoder result: %v", err)
	}
	if decResult.ConvertedCount != 1 {
		t.Fatalf("expected 1 converted decoder, got %d", decResult.ConvertedCount)
	}
	dec := decResult.Decoders[0]
	if !strings.Contains(dec.Regex, "(?P<user>") || !strings.Contains(dec.Regex, "(?P<client>") {
		t.Errorf("expected named groups in regex: %s", dec.Regex)
	}

	// 3. Test convert_and_add_wazuh_rule
	addRes, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "convert_and_add_wazuh_rule",
		Arguments: map[string]any{
			"xml": wazuhXML,
		},
	})
	if err != nil || addRes.IsError || len(addRes.Content) == 0 {
		t.Fatalf("convert_and_add_wazuh_rule failed: %v", err)
	}
	var addResult mcpConvertAndAddResult
	if err := json.Unmarshal([]byte(addRes.Content[0].(*mcp.TextContent).Text), &addResult); err != nil {
		t.Fatalf("failed to unmarshal convert_and_add_wazuh_rule result: %v", err)
	}
	if addResult.AddedCount < 3 {
		t.Fatalf("expected 3 added rules, got %d", addResult.AddedCount)
	}

	// 4. Verify rule can be fetched via get_sigma_rule
	getRes, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_sigma_rule",
		Arguments: map[string]any{
			"id": "wazuh-5710",
		},
	})
	if err != nil || getRes.IsError || len(getRes.Content) == 0 {
		t.Fatalf("get_sigma_rule wazuh-5710 failed: %v", err)
	}
	rYAML := getRes.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(rYAML, "wazuh-5710") || !strings.Contains(rYAML, "illegal user") {
		t.Errorf("fetched rule content unexpected: %s", rYAML)
	}
}
