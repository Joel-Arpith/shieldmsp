// Command mcp-server is ShieldMSP's Layer 1 ingestion server: a minimal
// hand-rolled MCP (JSON-RPC 2.0 over newline-delimited stdio) server
// exposing Microsoft Graph security data. No MCP SDK dependency — the
// protocol surface used here is three methods, not worth pulling in a
// library for.
//
// Run with no args to serve MCP on stdio. Run with `graph:verify` to print
// the Phase A/B acceptance checklist against the tenant in the environment.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"shieldmsp/internal/config"
	"shieldmsp/internal/graph"
	"shieldmsp/internal/normalize"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "graph:verify" {
		runVerify()
		return
	}
	runMCPServer()
}

// --- graph:verify ---

func runVerify() {
	ctx := context.Background()
	fmt.Println("ShieldMSP Layer 1 — graph:verify")
	fmt.Println()

	cfg, err := config.FromEnv()
	if err != nil {
		fmt.Printf("[FAIL] login: %v\n", err)
		os.Exit(1)
	}

	ts := graph.NewTokenSource(cfg.TenantID, cfg.ClientID, cfg.ClientSecret)
	roles, err := ts.Roles(ctx)
	if err != nil {
		fmt.Printf("[FAIL] login: %v\n", err)
		os.Exit(1)
	}
	if !containsString(roles, "SecurityAlert.Read.All") {
		fmt.Printf("[FAIL] login: token acquired but roles=%v is missing SecurityAlert.Read.All (admin consent likely wasn't granted)\n", roles)
		os.Exit(1)
	}
	fmt.Println("[PASS] login: token acquired, roles include SecurityAlert.Read.All")

	client := graph.NewClient(ts)
	rawAlerts, err := client.GetAlerts(ctx, 0, "")
	if err != nil {
		fmt.Printf("[FAIL] graph connected: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[PASS] graph connected: /security/alerts_v2 returned 200")

	if len(rawAlerts) == 0 {
		fmt.Println("[PASS] alerts retrieved: tenant has no alerts (empty value[] is a valid pass, not a failure)")
	} else {
		fmt.Printf("[PASS] alerts retrieved: %d alert(s)\n", len(rawAlerts))
	}

	alerts, shieldAlerts, err := decodeAndNormalize(rawAlerts, cfg.OrgID)
	if err != nil {
		fmt.Printf("[FAIL] normalized: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[PASS] normalized: %d Graph alert(s) -> %d ShieldMSP alert(s)\n", len(rawAlerts), len(shieldAlerts))

	devices := normalize.ExtractDevices(alerts, cfg.OrgID)
	fmt.Printf("[PASS] devices retrieved: %d device(s) from evidence dedup\n", len(devices))
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func decodeAndNormalize(raw []json.RawMessage, orgID string) ([]normalize.GraphAlert, []normalize.ShieldAlert, error) {
	alerts := make([]normalize.GraphAlert, 0, len(raw))
	shieldAlerts := make([]normalize.ShieldAlert, 0, len(raw))
	now := time.Now()
	for _, r := range raw {
		var a normalize.GraphAlert
		if err := json.Unmarshal(r, &a); err != nil {
			return nil, nil, fmt.Errorf("decode graph alert: %w", err)
		}
		alerts = append(alerts, a)
		sa, err := normalize.NormalizeAlert(a, r, orgID, now)
		if err != nil {
			return nil, nil, err
		}
		shieldAlerts = append(shieldAlerts, sa)
	}
	return alerts, shieldAlerts, nil
}

// --- MCP stdio server ---

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type toolHandler func(ctx context.Context, args map[string]any) (any, error)

type tool struct {
	def     toolDef
	handler toolHandler
}

func runMCPServer() {
	cfg, cfgErr := config.FromEnv()

	var client *graph.Client
	orgID := ""
	if cfgErr == nil {
		client = graph.NewClient(graph.NewTokenSource(cfg.TenantID, cfg.ClientID, cfg.ClientSecret))
		orgID = cfg.OrgID
	}
	tools := registerTools(client, orgID, cfgErr)

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	out := json.NewEncoder(os.Stdout)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			continue // malformed frame: nothing sane to address a reply to
		}
		if resp := handle(req, tools); resp != nil {
			_ = out.Encode(resp)
		}
	}
}

func handle(req rpcRequest, tools map[string]tool) *rpcResponse {
	switch req.Method {
	case "initialize":
		return result(req.ID, map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "shieldmsp-mcp-server", "version": "0.1.0"},
		})
	case "notifications/initialized":
		return nil
	case "tools/list":
		names := make([]string, 0, len(tools))
		for n := range tools {
			names = append(names, n)
		}
		sort.Strings(names)
		defs := make([]toolDef, 0, len(names))
		for _, n := range names {
			defs = append(defs, tools[n].def)
		}
		return result(req.ID, map[string]any{"tools": defs})
	case "tools/call":
		return handleToolCall(req, tools)
	default:
		if len(req.ID) == 0 {
			return nil // unrecognized notification: no reply expected
		}
		return errResult(req.ID, -32601, "method not found: "+req.Method)
	}
}

func handleToolCall(req rpcRequest, tools map[string]tool) *rpcResponse {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return errResult(req.ID, -32602, "invalid params: "+err.Error())
	}
	t, ok := tools[params.Name]
	if !ok {
		return errResult(req.ID, -32602, "unknown tool: "+params.Name)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := t.handler(ctx, params.Arguments)
	if err != nil {
		return result(req.ID, toolErrorContent(err))
	}
	text, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return result(req.ID, toolErrorContent(err))
	}
	return result(req.ID, map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(text)}},
	})
}

// toolErrorContent turns an error into MCP's tool-result-with-isError shape
// rather than a protocol-level error, per the MCP spec: a tool that fails is
// a normal result, not a broken RPC call. License/consent errors get a
// message a UI can show verbatim ("requires Entra ID P1", etc).
func toolErrorContent(err error) map[string]any {
	msg := err.Error()
	var le *graph.LicenseError
	var ce *graph.ConsentError
	switch {
	case errors.As(err, &le):
		msg = fmt.Sprintf("requires a Microsoft license this tenant doesn't have: %s", le.Message)
	case errors.As(err, &ce):
		msg = fmt.Sprintf("requires admin consent that hasn't been granted: %s", ce.Message)
	}
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": msg}},
		"isError": true,
	}
}

func result(id json.RawMessage, v any) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: id, Result: v}
}

func errResult(id json.RawMessage, code int, msg string) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

// --- tool registry ---

func registerTools(client *graph.Client, orgID string, cfgErr error) map[string]tool {
	tools := map[string]tool{}
	noArgs := map[string]any{"type": "object", "properties": map[string]any{}}

	add := func(name, desc string, schema map[string]any, h toolHandler) {
		tools[name] = tool{
			def: toolDef{Name: name, Description: desc, InputSchema: schema},
			handler: func(ctx context.Context, args map[string]any) (any, error) {
				if cfgErr != nil {
					return nil, fmt.Errorf("shieldmsp not configured (run Phase A first): %w", cfgErr)
				}
				return h(ctx, args)
			},
		}
	}

	add("get_security_alerts", "Fetch Microsoft Defender security alerts, normalized to the ShieldMSP schema.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"limit":  map[string]any{"type": "integer", "description": "Max alerts to return, 0 for all"},
				"filter": map[string]any{"type": "string", "description": "OData $filter, e.g. severity eq 'high'"},
			},
		},
		func(ctx context.Context, args map[string]any) (any, error) {
			raw, err := client.GetAlerts(ctx, intArg(args, "limit", 0), strArg(args, "filter"))
			if err != nil {
				return nil, err
			}
			_, shieldAlerts, err := decodeAndNormalize(raw, orgID)
			return shieldAlerts, err
		})

	add("list_incidents", "List Microsoft Defender security incidents.", noArgs,
		func(ctx context.Context, _ map[string]any) (any, error) { return rawJSON(client.ListIncidents(ctx)) })

	add("list_users", "List Entra ID users.", noArgs,
		func(ctx context.Context, _ map[string]any) (any, error) { return rawJSON(client.ListUsers(ctx)) })

	add("list_devices", "List devices derived from alert evidence, deduped by device ID.", noArgs,
		func(ctx context.Context, _ map[string]any) (any, error) {
			raw, err := client.GetAlerts(ctx, 0, "")
			if err != nil {
				return nil, err
			}
			alerts, _, err := decodeAndNormalize(raw, orgID)
			if err != nil {
				return nil, err
			}
			return normalize.ExtractDevices(alerts, orgID), nil
		})

	add("get_signin_logs", "Fetch Entra ID sign-in logs. Requires Entra ID P1.", noArgs,
		func(ctx context.Context, _ map[string]any) (any, error) { return rawJSON(client.GetSignInLogs(ctx)) })

	add("get_risky_users", "Fetch Entra ID Protection risky users. Requires Entra ID P2.", noArgs,
		func(ctx context.Context, _ map[string]any) (any, error) { return rawJSON(client.GetRiskyUsers(ctx)) })

	deviceIDSchema := map[string]any{
		"type":       "object",
		"properties": map[string]any{"deviceId": map[string]any{"type": "string"}},
		"required":   []string{"deviceId"},
	}
	add("get_device", "Get a single device's detail from current alert evidence.", deviceIDSchema,
		func(ctx context.Context, args map[string]any) (any, error) {
			id := strArg(args, "deviceId")
			raw, err := client.GetAlerts(ctx, 0, "")
			if err != nil {
				return nil, err
			}
			alerts, _, err := decodeAndNormalize(raw, orgID)
			if err != nil {
				return nil, err
			}
			for _, d := range normalize.ExtractDevices(alerts, orgID) {
				if d.ExternalID == id {
					return d, nil
				}
			}
			return nil, fmt.Errorf("device %q not found in current alert evidence", id)
		})

	stub := func(name, desc string) {
		tools[name] = tool{
			def: toolDef{Name: name, Description: desc, InputSchema: deviceIDSchema},
			handler: func(ctx context.Context, args map[string]any) (any, error) {
				return nil, fmt.Errorf("%s: not on Microsoft Graph (Defender API required); see Machine.Isolate", name)
			},
		}
	}
	stub("isolate_device", "Not implemented: device isolation requires the Defender for Endpoint API, not Graph.")
	stub("release_device", "Not implemented: device release requires the Defender for Endpoint API, not Graph.")

	return tools
}

func rawJSON(raw []json.RawMessage, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(raw))
	for _, r := range raw {
		var v any
		if err := json.Unmarshal(r, &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func intArg(args map[string]any, key string, def int) int {
	v, ok := args[key]
	if !ok {
		return def
	}
	if f, ok := v.(float64); ok { // JSON numbers decode as float64
		return int(f)
	}
	return def
}

func strArg(args map[string]any, key string) string {
	v, _ := args[key].(string)
	return v
}
