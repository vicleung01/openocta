package runtime

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/stellarlinkco/agentsdk-go/pkg/middleware"
	"github.com/stellarlinkco/agentsdk-go/pkg/model"
)

// ---------------------------------------------------------------------------
// MCP SQL Guard Middleware
// ---------------------------------------------------------------------------
// Intercepts MCP tool calls that contain SQL and blocks dangerous operations
// (DROP TABLE/DATABASE/INDEX, ALTER TABLE, TRUNCATE, DELETE/UPDATE without WHERE).
//
// This closes a security gap: MCP tool paths bypass the command_policy +
// approval queue + SQL validation layers that protect the built-in bash tool.
// SQL Guard adds protection at the middleware level, covering all tools
// regardless of their entry point.
// ---------------------------------------------------------------------------

// sqlParamKeys are the known parameter names that may contain SQL statements.
// Multiple MCP tools use different key names; we check all of them.
var sqlParamKeys = []string{"sql", "query", "statement", "command"}

// denyPatterns are regex patterns for dangerous SQL operations that are always
// blocked regardless of context (no legitimate use in DBA assistant).
// Each pattern is checked against individual SQL statements (split by semicolons).
var denyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bDROP\s+TABLE\b`),
	regexp.MustCompile(`(?i)\bDROP\s+DATABASE\b`),
	regexp.MustCompile(`(?i)\bDROP\s+INDEX\b`),
	regexp.MustCompile(`(?i)\bALTER\s+TABLE\b`),
	regexp.MustCompile(`(?i)\bTRUNCATE\s+\w+`),
}

// conditionalPatterns match operations that are dangerous only when missing WHERE.
// Key = pattern to detect the operation, check = function that returns true if the
// statement is dangerous (e.g., no WHERE clause).
var conditionalPatterns = []struct {
	pattern *regexp.Regexp
	// dangerous returns true if the matched statement should be blocked.
	dangerous func(stmt string) bool
}{
	{
		pattern: regexp.MustCompile(`(?i)\bDELETE\s+FROM\s+\w+`),
		dangerous: func(stmt string) bool {
			// Block DELETE FROM that has no WHERE clause.
			return !regexp.MustCompile(`(?i)\bWHERE\b`).MatchString(stmt)
		},
	},
	{
		pattern: regexp.MustCompile(`(?i)\bUPDATE\s+\w+\s+SET\b`),
		dangerous: func(stmt string) bool {
			// Block UPDATE ... SET that has no WHERE clause.
			return !regexp.MustCompile(`(?i)\bWHERE\b`).MatchString(stmt)
		},
	},
}

// mcpSQLGuardMiddleware returns a middleware that intercepts dangerous SQL
// in MCP tool arguments. It checks multiple SQL parameter names against deny
// patterns and blocks execution if a match is found.
func mcpSQLGuardMiddleware() middleware.Middleware {
	return middleware.Funcs{
		Identifier: "openocta-sql-guard",
		OnBeforeTool: func(_ context.Context, st *middleware.State) error {
			call, ok := st.ToolCall.(model.ToolCall)
			if !ok {
				return nil
			}

			// Extract SQL from known parameter names.
			sql := extractSQL(call.Arguments)
			if sql == "" {
				return nil
			}

			// Split multi-statement SQL and check each independently.
			statements := splitStatements(sql)
			for _, stmt := range statements {
				stmt = strings.TrimSpace(stmt)
				if stmt == "" {
					continue
				}
				// Check unconditional deny patterns.
				for _, pat := range denyPatterns {
					if pat.MatchString(stmt) {
						return fmt.Errorf("SQL guard: 危险操作被拦截 (%s). 如需执行请联系 DBA 走审批流程", pat.String())
					}
				}
				// Check conditional patterns (e.g., DELETE/UPDATE without WHERE).
				for _, cp := range conditionalPatterns {
					if cp.pattern.MatchString(stmt) && cp.dangerous(stmt) {
						return fmt.Errorf("SQL guard: 危险操作被拦截 (%s 缺少 WHERE 条件). 如需执行请联系 DBA 走审批流程", cp.pattern.String())
					}
				}
			}
			return nil
		},
	}
}

// extractSQL tries multiple known parameter keys to find SQL content.
func extractSQL(args map[string]any) string {
	for _, key := range sqlParamKeys {
		if v, ok := args[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// splitStatements splits SQL by semicolons to handle multi-statement input.
// This prevents attacks like "DELETE FROM users; SELECT 1;" where the dangerous
// operation is hidden behind a trailing statement.
func splitStatements(sql string) []string {
	parts := strings.Split(sql, ";")
	// Filter empty strings from trailing semicolons.
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
