package runtime

import (
	"context"
	"strings"

	"github.com/stellarlinkco/agentsdk-go/pkg/middleware"
)

// userContextMiddleware 在 BeforeAgent 阶段从 sessionKey 解析调用者真实姓名,
// 注入 state.Values["caller_user"],供后续 dbAuthGuardMiddleware 鉴权使用。
//
// sessionKey 格式由 tctp_bridge.py 写死:employee-main-tctp:{user}
// (user = 真实姓名,与 CMDB wb_staff.cn_name 对齐)。
// 此中间件只注入、不阻断,且不依赖 AI 传参(铁律:不依赖 prompt 自觉)。
func userContextMiddleware() middleware.Middleware {
	return middleware.Funcs{
		Identifier: "openocta-user-context",
		OnBeforeAgent: func(_ context.Context, st *middleware.State) error {
			if st == nil || st.Values == nil {
				return nil
			}
			sid, _ := st.Values["session_id"].(string)
			if sid == "" {
				return nil
			}
			if u := parseTctpUser(sid); u != "" {
				st.Values["caller_user"] = u
			}
			return nil
		},
	}
}

// parseTctpUser 从 "employee-main-tctp:{user}" 提取 user。
func parseTctpUser(sid string) string {
	const prefix = "employee-main-tctp:"
	if i := strings.Index(sid, prefix); i >= 0 {
		return strings.TrimSpace(sid[i+len(prefix):])
	}
	return ""
}
