package runtime

import (
	"context"
	"testing"

	"github.com/stellarlinkco/agentsdk-go/pkg/middleware"
	"github.com/stellarlinkco/agentsdk-go/pkg/model"
)

func TestSQLGuard_BlocksDangerousSQL(t *testing.T) {
	guard := mcpSQLGuardMiddleware()

	tests := []struct {
		name    string
		sql     string
		blocked bool
	}{
		// --- DROP operations ---
		{"DROP TABLE", "DROP TABLE users;", true},
		{"drop table lowercase", "drop table users;", true},
		{"DROP DATABASE", "DROP DATABASE production;", true},
		{"DROP INDEX", "DROP INDEX idx_name ON users;", true},

		// --- ALTER ---
		{"ALTER TABLE", "ALTER TABLE users ADD COLUMN age INT;", true},

		// --- TRUNCATE ---
		{"TRUNCATE", "TRUNCATE users;", true},

		// --- DELETE ---
		{"DELETE without WHERE", "DELETE FROM users;", true},
		{"DELETE with WHERE", "DELETE FROM users WHERE id = 1;", false},

		// --- UPDATE ---
		{"UPDATE without WHERE", "UPDATE users SET role = 'admin';", true},
		{"UPDATE with WHERE", "UPDATE users SET name = 'test' WHERE id = 1;", false},

		// --- Safe operations ---
		{"SELECT", "SELECT * FROM users;", false},
		{"SHOW PROCESSLIST", "SHOW PROCESSLIST;", false},
		{"INSERT", "INSERT INTO users (name) VALUES ('test');", false},
		{"empty SQL", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &middleware.State{
				ToolCall: model.ToolCall{
					Name: "tdsql_login_set",
					Arguments: map[string]any{
						"sql": tt.sql,
					},
				},
			}
			err := guard.(middleware.Funcs).OnBeforeTool(context.Background(), state)
			if tt.blocked && err == nil {
				t.Errorf("expected SQL to be blocked: %q", tt.sql)
			}
			if !tt.blocked && err != nil {
				t.Errorf("expected SQL to pass: %q, got error: %v", tt.sql, err)
			}
		})
	}
}

func TestSQLGuard_MultiStatementBypass(t *testing.T) {
	guard := mcpSQLGuardMiddleware()

	tests := []struct {
		name    string
		sql     string
		blocked bool
	}{
		// Multi-statement with dangerous op hidden behind trailing statement.
		{"DELETE then SELECT", "DELETE FROM users; SELECT 1;", true},
		{"SELECT then DROP", "SELECT 1; DROP TABLE users;", true},
		{"UPDATE then SELECT", "UPDATE users SET role='admin'; SELECT 1;", true},
		// Safe multi-statement.
		{"two SELECTs", "SELECT 1; SELECT 2;", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &middleware.State{
				ToolCall: model.ToolCall{
					Name: "tdsql_login_set",
					Arguments: map[string]any{
						"sql": tt.sql,
					},
				},
			}
			err := guard.(middleware.Funcs).OnBeforeTool(context.Background(), state)
			if tt.blocked && err == nil {
				t.Errorf("expected SQL to be blocked: %q", tt.sql)
			}
			if !tt.blocked && err != nil {
				t.Errorf("expected SQL to pass: %q, got error: %v", tt.sql, err)
			}
		})
	}
}

func TestSQLGuard_AlternateParamKeys(t *testing.T) {
	guard := mcpSQLGuardMiddleware()

	tests := []struct {
		name    string
		key     string
		sql     string
		blocked bool
	}{
		// "query" parameter should also be checked.
		{"query key DROP", "query", "DROP TABLE users;", true},
		{"statement key DELETE", "statement", "DELETE FROM users;", true},
		{"command key UPDATE", "command", "UPDATE users SET x=1;", true},
		// Unknown key → not checked.
		{"unknown key passes", "data", "DROP TABLE users;", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &middleware.State{
				ToolCall: model.ToolCall{
					Name: "some_tool",
					Arguments: map[string]any{
						tt.key: tt.sql,
					},
				},
			}
			err := guard.(middleware.Funcs).OnBeforeTool(context.Background(), state)
			if tt.blocked && err == nil {
				t.Errorf("expected SQL to be blocked via key %q: %q", tt.key, tt.sql)
			}
			if !tt.blocked && err != nil {
				t.Errorf("expected SQL to pass via key %q: %q, got error: %v", tt.key, tt.sql, err)
			}
		})
	}
}

func TestSQLGuard_SkipsNonSQLTools(t *testing.T) {
	guard := mcpSQLGuardMiddleware()

	state := &middleware.State{
		ToolCall: model.ToolCall{
			Name: "tdsql_list_sets",
			Arguments: map[string]any{
				"cluster_id": "1",
			},
		},
	}
	err := guard.(middleware.Funcs).OnBeforeTool(context.Background(), state)
	if err != nil {
		t.Errorf("expected non-SQL tool to pass, got error: %v", err)
	}
}
