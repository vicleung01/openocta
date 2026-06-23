package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/stellarlinkco/agentsdk-go/pkg/middleware"
	"github.com/stellarlinkco/agentsdk-go/pkg/model"
)

// dbAuthGuardMiddleware 在 BeforeTool 阶段拦截数据库类工具调用,通过 cmdb-auth MCP(:8942)
// 判定调用者运维组是否含目标库的子系统,越权则阻断(block 模式)或仅记录(audit 模式)。
//
// 设计原则(与 plan 一致):
//   - 不依赖 AI 传 user:从 state.Values["caller_user"](userContextMiddleware 注入)取
//   - CMDB/cmdb-auth 不可达 → fail-open(放行+日志),绝不因鉴权服务故障阻断 DBA 生产
//   - db_name 缺失(全局查询如 SHOW PROCESSLIST)→ 放行+审计
//   - 特权账号(openocta_ro)→ bypass
//   - 模式由 env OPENOCTA_DB_AUTH_MODE 控制:off(默认,关)/ audit(只记)/ block(拦)
//
// 调用 cmdb-auth: POST {DBAUTH_URL}/  JSON-RPC tools/call check_db_access {user,db_name}
var (
	dbAuthMode   = strings.ToLower(strings.TrimSpace(os.Getenv("OPENOCTA_DB_AUTH_MODE")))
	dbAuthURL    = envDefault("OPENOCTA_DB_AUTH_URL", "http://127.0.0.1:8942")
	dbAuthClient = &http.Client{Timeout: 3 * time.Second}
	dbParamKeys  = []string{"db_name", "database", "db", "schema"}
	bypassUsers  = envDefault("OPENOCTA_DB_AUTH_BYPASS", "openocta_ro")
)

// db 类工具名前缀(OpenOcta 工具含库名/实例的),非此前缀直接放行,零成本。
var dbToolPrefixes = []string{"dba_tdsql_", "dba_cloud_", "dba_mysql_", "dba_tidb_", "dba_dm_"}

// 实例级参数名(TDSQL dbinstance_name / set 等)。注意:set 级有歧义(一 set 多库),
// 但工具若显式传 dbinstance_name 则精确。instance 优先于 db_name 判定。
var instanceParamKeys = []string{"instance", "dbinstance_name", "instance_name", "tdset", "set_name"}

func envDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func dbAuthGuardMiddleware() middleware.Middleware {
	return middleware.Funcs{
		Identifier: "openocta-db-auth-guard",
		OnBeforeTool: func(_ context.Context, st *middleware.State) error {
			if dbAuthMode == "" || dbAuthMode == "off" {
				return nil
			}
			call, ok := st.ToolCall.(model.ToolCall)
			if !ok {
				return nil
			}
			if !isDbTool(call.Name) {
				return nil
			}
			user, _ := st.Values["caller_user"].(string)
			instance := extractInstance(call.Arguments)
			dbName := extractDbName(call.Arguments)

			// 无目标(全局查询如 SHOW PROCESSLIST)→ 放行
			if instance == "" && dbName == "" {
				return nil
			}
			target := instance
			if target == "" {
				target = dbName
			}
			// 特权账号 bypass
			if isBypassUser(user) {
				auditLog(user, target, "bypass", "")
				return nil
			}

			// instance 优先(实例级),否则 db_name(库级)
			var allowed bool
			var reason, subsystem string
			var err error
			if instance != "" {
				allowed, reason, subsystem, err = checkInstanceAccess(user, instance)
			} else {
				allowed, reason, subsystem, err = checkDbAccess(user, dbName)
			}
			if err != nil {
				// cmdb-auth 不可达 → fail-open
				log.Printf("[db-auth] FAIL-OPEN user=%s target=%s err=%v", user, target, err)
				return nil
			}
			if allowed {
				auditLog(user, target, "allow", subsystem)
				return nil
			}
			// 越权
			if dbAuthMode == "block" {
				return fmt.Errorf("db-auth: 越权拦截 — %s(归属 %s)不在您的权限范围内。建议联系该子系统运维组申请权限,或回复【转人工】",
					target, subsystem)
			}
			auditLog(user, target, "deny("+reason+")", subsystem)
			return nil
		},
	}
}

func isDbTool(name string) bool {
	n := strings.ToLower(name)
	for _, p := range dbToolPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

func extractDbName(args map[string]any) string {
	if args == nil {
		return ""
	}
	for _, k := range dbParamKeys {
		if v, ok := args[k].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func extractInstance(args map[string]any) string {
	if args == nil {
		return ""
	}
	for _, k := range instanceParamKeys {
		if v, ok := args[k].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func isBypassUser(user string) bool {
	u := strings.TrimSpace(user)
	if u == "" {
		return false
	}
	for _, b := range strings.Split(bypassUsers, ",") {
		if strings.TrimSpace(b) == u {
			return true
		}
	}
	return false
}

// checkAccess 通用 HTTP 调 cmdb-auth MCP(:8942)。method=check_db_access/check_instance_access。
// 返回 (allowed, reason, subsystem, error)。error 表示鉴权服务不可达(fail-open)。
func checkAccess(user, method, paramName, value string) (bool, string, string, error) {
	reqBody := map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name":      method,
			"arguments": map[string]any{"user": user, paramName: value},
		},
	}
	body, _ := json.Marshal(reqBody)
	req, err := http.NewRequest("POST", dbAuthURL+"/", bytes.NewReader(body))
	if err != nil {
		return false, "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Caller-User", user)
	resp, err := dbAuthClient.Do(req)
	if err != nil {
		return false, "", "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", "", err
	}
	// MCP 响应:{result:{content:[{type:text, text:"<verdict json>"}]}}
	var mcp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &mcp); err != nil || len(mcp.Result.Content) == 0 {
		return false, "", "", fmt.Errorf("bad cmdb-auth response: %s", truncate(string(raw), 120))
	}
	var v struct {
		Allowed   bool   `json:"allowed"`
		Reason    string `json:"reason"`
		Subsystem string `json:"subsystem"`
	}
	if err := json.Unmarshal([]byte(mcp.Result.Content[0].Text), &v); err != nil {
		return false, "", "", err
	}
	return v.Allowed, v.Reason, v.Subsystem, nil
}

func checkDbAccess(user, dbName string) (bool, string, string, error) {
	return checkAccess(user, "check_db_access", "db_name", dbName)
}

func checkInstanceAccess(user, instance string) (bool, string, string, error) {
	return checkAccess(user, "check_instance_access", "instance", instance)
}

func auditLog(user, db, decision, subsystem string) {
	log.Printf("[db-auth] user=%s db=%s subsystem=%s decision=%s", user, db, subsystem, decision)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
