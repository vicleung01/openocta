package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// Planner creates Plan DAGs from templates or natural language.
type Planner struct {
	mu        sync.RWMutex
	templates map[string]*Plan
}

// NewPlanner creates a planner with built-in DBA templates.
func NewPlanner() *Planner {
	// deep copy builtin templates so callers can modify plans without affecting the originals
	templates := make(map[string]*Plan, len(builtinTemplates))
	for k, v := range builtinTemplates {
		templates[k] = clonePlan(v)
	}
	return &Planner{templates: templates}
}

// ListTemplates returns the names of all registered templates.
func (p *Planner) ListTemplates() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	names := make([]string, 0, len(p.templates))
	for k := range p.templates {
		names = append(names, k)
	}
	return names
}

// GetTemplate returns a cloned copy of the named template.
func (p *Planner) GetTemplate(name string) (*Plan, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	t, ok := p.templates[name]
	if !ok {
		return nil, fmt.Errorf("planner: template %q not found", name)
	}
	return clonePlan(t), nil
}

// RegisterTemplate adds or replaces a template by name.
func (p *Planner) RegisterTemplate(name string, plan *Plan) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.templates[name] = clonePlan(plan)
}

// BuildPlanFromTemplate creates an executable Plan from a template.
// It sets the plan ID, resets all node statuses to pending, and initializes context.
func BuildPlanFromTemplate(tmpl *Plan, planID string) *Plan {
	plan := clonePlan(tmpl)
	plan.ID = planID
	plan.Status = PlanPending
	if plan.Context == nil {
		plan.Context = map[string]string{}
	}
	for _, n := range plan.Nodes {
		n.Status = NodePending
	}
	return plan
}

// --- LLM-based plan generation ---

const planGenerationSystemPrompt = `你是一个数据库运维(DBA)工作流规划助手，负责将用户的自然语言任务描述分解为一个有向无环图(DAG)工作流。

请将任务拆分为多个有序步骤，每个步骤对应一个图中节点。返回严格符合以下JSON格式的Plan对象（直接返回JSON，不要包含markdown代码块标记或任何说明文字）：

{
  "name": "工作流名称（中文）",
  "nodes": {
    "step_id": {
      "id": "step_id",
      "name": "步骤名称",
      "description": "步骤详细说明",
      "prompt": "步骤的执行指令，告知AI助手在此步骤的具体操作内容，需要什么数据、用什么工具",
      "tools": ["tool_name"],
      "depends_on": ["upstream_step"],
      "max_retries": 1,
      "require_approval": false,
      "parallel": false,
      "output_key": "output_var_name"
    }
  },
  "entry_node": "first_step"
}

规则：
1. 起始节点(entry_node)的depends_on省略或为空数组
2. 后续节点根据任务自然流程排列。无依赖关系的步骤可并行执行(parallel设为true)
3. 需要人工确认的危险操作（删数据、改配置、变更）设置require_approval: true
4. 每个节点必须有prompt和output_key
5. 节点ID用英文小写加下划线
6. depends_on省略表示无依赖
7. 返回纯JSON，不要有任何前后说明文字`

// LLMGeneratePlan uses the callLLM function to decompose a natural language description into a Plan DAG.
// callLLM receives the full prompt and returns the LLM's raw text response.
func LLMGeneratePlan(ctx context.Context, description string, callLLM func(ctx context.Context, prompt string) (string, error)) (*Plan, error) {
	if strings.TrimSpace(description) == "" {
		return nil, fmt.Errorf("planner: empty description")
	}

	fullPrompt := planGenerationSystemPrompt + "\n\n用户需求：\n" + description

	raw, err := callLLM(ctx, fullPrompt)
	if err != nil {
		return nil, fmt.Errorf("planner: LLM call failed: %w", err)
	}

	plan, err := parsePlanJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("planner: parse failed: %w", err)
	}

	normalizePlan(plan)
	if err := validatePlan(plan); err != nil {
		return nil, fmt.Errorf("planner: validation failed: %w", err)
	}

	return plan, nil
}

// parsePlanJSON extracts a Plan from raw LLM output, handling markdown fences and extra text.
func parsePlanJSON(raw string) (*Plan, error) {
	s := strings.TrimSpace(raw)

	// Remove markdown code block fences if present (```json ... ```)
	if strings.HasPrefix(s, "```") {
		start := strings.Index(s, "{")
		end := strings.LastIndex(s, "}")
		if start >= 0 && end > start {
			s = s[start : end+1]
		}
	}

	// Fallback: find JSON object boundaries by brace matching
	braceStart := strings.Index(s, "{")
	braceEnd := strings.LastIndex(s, "}")
	if braceStart >= 0 && braceEnd > braceStart {
		s = s[braceStart : braceEnd+1]
	}

	var plan Plan
	if err := json.Unmarshal([]byte(s), &plan); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	if plan.Nodes == nil {
		plan.Nodes = map[string]*Node{}
	}

	return &plan, nil
}

// normalizePlan initializes fields that LLM-generated JSON may omit.
func normalizePlan(plan *Plan) {
	if plan.Status == "" {
		plan.Status = PlanPending
	}
	if plan.Context == nil {
		plan.Context = map[string]string{}
	}
	for _, n := range plan.Nodes {
		if n.ID == "" {
			n.ID = n.Name
		}
		if n.Status == "" {
			n.Status = NodePending
		}
	}
}

// validatePlan checks that a generated plan has required fields and valid references.
func validatePlan(plan *Plan) error {
	if plan.EntryNode == "" {
		return fmt.Errorf("entry_node is empty")
	}
	if len(plan.Nodes) == 0 {
		return fmt.Errorf("no nodes defined")
	}
	if _, ok := plan.Nodes[plan.EntryNode]; !ok {
		return fmt.Errorf("entry_node %q not found in nodes", plan.EntryNode)
	}
	for id, n := range plan.Nodes {
		if n.Prompt == "" {
			return fmt.Errorf("node %q: prompt is empty", id)
		}
		for _, dep := range n.DependsOn {
			if _, ok := plan.Nodes[dep]; !ok {
				return fmt.Errorf("node %q: depends_on %q not found", id, dep)
			}
		}
	}
	if hasCycle(plan) {
		return fmt.Errorf("plan contains a cycle")
	}
	return nil
}

// hasCycle detects cycles in the dependency graph using DFS coloring.
func hasCycle(plan *Plan) bool {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make(map[string]int, len(plan.Nodes))
	for id := range plan.Nodes {
		color[id] = white
	}

	var dfs func(id string) bool
	dfs = func(id string) bool {
		color[id] = gray
		n := plan.Nodes[id]
		for _, dep := range n.DependsOn {
			switch color[dep] {
			case gray:
				return true
			case white:
				if dfs(dep) {
					return true
				}
			}
		}
		color[id] = black
		return false
	}

	for id := range plan.Nodes {
		if color[id] == white {
			if dfs(id) {
				return true
			}
		}
	}
	return false
}

// clonePlan creates a deep copy of a Plan.
func clonePlan(src *Plan) *Plan {
	if src == nil {
		return nil
	}
	dst := &Plan{
		ID:        src.ID,
		Name:      src.Name,
		EntryNode: src.EntryNode,
		Status:    src.Status,
	}
	if src.Nodes != nil {
		dst.Nodes = make(map[string]*Node, len(src.Nodes))
		for k, v := range src.Nodes {
			if v == nil {
				continue
			}
			cp := *v
			if v.Tools != nil {
				cp.Tools = append([]string(nil), v.Tools...)
			}
			if v.DependsOn != nil {
				cp.DependsOn = append([]string(nil), v.DependsOn...)
			}
			if v.OnSuccess != nil {
				cp.OnSuccess = make(map[string]string, len(v.OnSuccess))
				for ok, ov := range v.OnSuccess {
					cp.OnSuccess[ok] = ov
				}
			}
			dst.Nodes[k] = &cp
		}
	}
	if src.Context != nil {
		dst.Context = make(map[string]string, len(src.Context))
		for k, v := range src.Context {
			dst.Context[k] = v
		}
	}
	return dst
}
