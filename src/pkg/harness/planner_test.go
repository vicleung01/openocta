package harness

import (
	"context"
	"fmt"
	"testing"
)

func TestNewPlanner_HasBuiltinTemplates(t *testing.T) {
	p := NewPlanner()
	templates := p.ListTemplates()
	if len(templates) == 0 {
		t.Fatal("expected built-in templates, got none")
	}

	for _, name := range []string{"slow_query_analysis", "deadlock_analysis", "disk_space_check", "health_check"} {
		plan, err := p.GetTemplate(name)
		if err != nil {
			t.Fatalf("expected template %q, got error: %v", name, err)
		}
		if plan.EntryNode == "" {
			t.Fatalf("template %q has no entry node", name)
		}
		if len(plan.Nodes) == 0 {
			t.Fatalf("template %q has no nodes", name)
		}
	}
}

func TestBuildPlanFromTemplate_ResetsStatus(t *testing.T) {
	p := NewPlanner()
	tmpl, _ := p.GetTemplate("slow_query_analysis")

	// set some status on the template (should not affect the built plan)
	tmpl.Nodes["collect"].Status = NodeSucceeded

	plan := BuildPlanFromTemplate(tmpl, "test-plan-1")
	if plan.ID != "test-plan-1" {
		t.Fatalf("expected plan ID 'test-plan-1', got %q", plan.ID)
	}
	if plan.Status != PlanPending {
		t.Fatalf("expected plan status PlanPending, got %s", plan.Status)
	}
	for id, n := range plan.Nodes {
		if n.Status != NodePending {
			t.Fatalf("expected node %s status NodePending, got %s", id, n.Status)
		}
	}
}

func TestBuildPlanFromTemplate_DeepCopy(t *testing.T) {
	p := NewPlanner()
	tmpl, _ := p.GetTemplate("slow_query_analysis")
	plan := BuildPlanFromTemplate(tmpl, "test-copy")

	// modifying the built plan should not affect the template
	plan.Nodes["collect"].Prompt = "modified"
	plan.Context["foo"] = "bar"

	tmplCopy, _ := p.GetTemplate("slow_query_analysis")
	if tmplCopy.Nodes["collect"].Prompt == "modified" {
		t.Fatal("template was mutated by plan modification")
	}
}

func TestRegisterTemplate(t *testing.T) {
	p := NewPlanner()
	custom := &Plan{
		Name: "自定义巡检",
		Nodes: map[string]*Node{
			"step1": {ID: "step1", Name: "第一步", Prompt: "do something"},
		},
		EntryNode: "step1",
	}
	p.RegisterTemplate("my_custom", custom)

	got, err := p.GetTemplate("my_custom")
	if err != nil {
		t.Fatalf("expected to get registered template: %v", err)
	}
	if got.Name != "自定义巡检" {
		t.Fatalf("expected name '自定义巡检', got %q", got.Name)
	}
}

func TestGetTemplate_NotFound(t *testing.T) {
	p := NewPlanner()
	_, err := p.GetTemplate("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent template")
	}
}

func TestSlowQueryTemplate_NodeDeps(t *testing.T) {
	p := NewPlanner()
	plan, _ := p.GetTemplate("slow_query_analysis")

	// verify DAG structure: collect → analyze → report → apply
	checkDep(t, plan, "collect", nil)
	checkDep(t, plan, "analyze", []string{"collect"})
	checkDep(t, plan, "report", []string{"analyze"})
	checkDep(t, plan, "apply", []string{"report"})

	if !plan.Nodes["apply"].RequireApproval {
		t.Fatal("expected 'apply' node to require approval")
	}
}

func TestHealthCheckTemplate_Parallel(t *testing.T) {
	p := NewPlanner()
	plan, _ := p.GetTemplate("health_check")

	// replication, performance, errors should be parallel
	for _, id := range []string{"replication", "performance", "errors"} {
		if !plan.Nodes[id].Parallel {
			t.Fatalf("expected node %q to be parallel", id)
		}
	}
	// report depends on all four check nodes
	reportDeps := plan.Nodes["report"].DependsOn
	expectedDeps := []string{"connections", "replication", "performance", "errors"}
	if len(reportDeps) != len(expectedDeps) {
		t.Fatalf("report has %d deps, expected %d", len(reportDeps), len(expectedDeps))
	}
}

// --- LLM plan generation tests ---

func TestParsePlanJSON_CleanJSON(t *testing.T) {
	raw := `{"name":"测试","nodes":{"s1":{"id":"s1","name":"步骤1","prompt":"执行操作","output_key":"out1"}},"entry_node":"s1"}`
	plan, err := parsePlanJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.EntryNode != "s1" {
		t.Fatalf("expected entry_node s1, got %s", plan.EntryNode)
	}
	if plan.Nodes["s1"] == nil {
		t.Fatal("expected node s1")
	}
}

func TestParsePlanJSON_MarkdownFence(t *testing.T) {
	raw := "```json\n{\"name\":\"测试\",\"nodes\":{\"s1\":{\"id\":\"s1\",\"name\":\"步骤1\",\"prompt\":\"操作\",\"output_key\":\"o\"}},\"entry_node\":\"s1\"}\n```"
	plan, err := parsePlanJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.EntryNode != "s1" {
		t.Fatalf("expected entry_node s1, got %s", plan.EntryNode)
	}
}

func TestParsePlanJSON_WithPrefixText(t *testing.T) {
	raw := `以下是生成的计划：
{"name":"测试","nodes":{"s1":{"id":"s1","name":"步骤1","prompt":"操作","output_key":"o"}},"entry_node":"s1"}
以上是JSON格式的计划`
	plan, err := parsePlanJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.EntryNode != "s1" {
		t.Fatalf("expected entry_node s1, got %s", plan.EntryNode)
	}
}

func TestParsePlanJSON_InvalidJSON(t *testing.T) {
	_, err := parsePlanJSON("not json at all")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestValidatePlan_MissingEntryNode(t *testing.T) {
	plan := &Plan{
		Nodes: map[string]*Node{"a": {ID: "a", Prompt: "do something"}},
	}
	err := validatePlan(plan)
	if err == nil {
		t.Fatal("expected error for missing entry_node")
	}
}

func TestValidatePlan_BadDependsOn(t *testing.T) {
	plan := &Plan{
		EntryNode: "a",
		Nodes: map[string]*Node{
			"a": {ID: "a", Prompt: "step a"},
			"b": {ID: "b", Prompt: "step b", DependsOn: []string{"nonexistent"}},
		},
	}
	err := validatePlan(plan)
	if err == nil {
		t.Fatal("expected error for bad depends_on")
	}
}

func TestValidatePlan_Cycle(t *testing.T) {
	plan := &Plan{
		EntryNode: "a",
		Nodes: map[string]*Node{
			"a": {ID: "a", Prompt: "step a", DependsOn: []string{"c"}},
			"b": {ID: "b", Prompt: "step b", DependsOn: []string{"a"}},
			"c": {ID: "c", Prompt: "step c", DependsOn: []string{"b"}},
		},
	}
	err := validatePlan(plan)
	if err == nil {
		t.Fatal("expected error for cycle")
	}
}

func TestValidatePlan_EmptyPrompt(t *testing.T) {
	plan := &Plan{
		EntryNode: "a",
		Nodes:     map[string]*Node{"a": {ID: "a"}},
	}
	err := validatePlan(plan)
	if err == nil {
		t.Fatal("expected error for empty prompt")
	}
}

func TestValidatePlan_Valid(t *testing.T) {
	plan := &Plan{
		EntryNode: "a",
		Nodes: map[string]*Node{
			"a": {ID: "a", Prompt: "step a", OutputKey: "out_a"},
			"b": {ID: "b", Prompt: "step b", DependsOn: []string{"a"}, OutputKey: "out_b"},
		},
	}
	err := validatePlan(plan)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNormalizePlan_SetsDefaults(t *testing.T) {
	plan := &Plan{
		EntryNode: "a",
		Nodes: map[string]*Node{
			"a": {ID: "a", Prompt: "step a"},
		},
	}
	normalizePlan(plan)
	if plan.Status != PlanPending {
		t.Fatalf("expected PlanPending, got %s", plan.Status)
	}
	if plan.Context == nil {
		t.Fatal("expected non-nil context")
	}
	if plan.Nodes["a"].Status != NodePending {
		t.Fatalf("expected NodePending, got %s", plan.Nodes["a"].Status)
	}
}

func TestLLMGeneratePlan_Success(t *testing.T) {
	mockLLM := func(ctx context.Context, prompt string) (string, error) {
		return `{"name":"测试计划","nodes":{"s1":{"id":"s1","name":"步骤1","prompt":"执行检查","output_key":"result"}},"entry_node":"s1"}`, nil
	}
	plan, err := LLMGeneratePlan(context.Background(), "检查数据库状态", mockLLM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.Name != "测试计划" {
		t.Fatalf("expected name '测试计划', got %q", plan.Name)
	}
	if plan.EntryNode != "s1" {
		t.Fatalf("expected entry_node s1, got %s", plan.EntryNode)
	}
	// verify normalizePlan was applied
	if plan.Status != PlanPending {
		t.Fatalf("expected PlanPending, got %s", plan.Status)
	}
}

func TestLLMGeneratePlan_EmptyDescription(t *testing.T) {
	mockLLM := func(ctx context.Context, prompt string) (string, error) {
		return "", nil
	}
	_, err := LLMGeneratePlan(context.Background(), "", mockLLM)
	if err == nil {
		t.Fatal("expected error for empty description")
	}
}

func TestLLMGeneratePlan_LLMError(t *testing.T) {
	mockLLM := func(ctx context.Context, prompt string) (string, error) {
		return "", fmt.Errorf("LLM unavailable")
	}
	_, err := LLMGeneratePlan(context.Background(), "test", mockLLM)
	if err == nil {
		t.Fatal("expected error for LLM failure")
	}
}

func TestLLMGeneratePlan_BadJSON(t *testing.T) {
	mockLLM := func(ctx context.Context, prompt string) (string, error) {
		return "{bad json", nil
	}
	_, err := LLMGeneratePlan(context.Background(), "test", mockLLM)
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

func checkDep(t *testing.T, plan *Plan, nodeID string, expectedDeps []string) {
	t.Helper()
	n, ok := plan.Nodes[nodeID]
	if !ok {
		t.Fatalf("node %q not found in plan", nodeID)
	}
	if len(expectedDeps) == 0 && len(n.DependsOn) != 0 {
		t.Fatalf("expected node %q to have no deps, got %v", nodeID, n.DependsOn)
	}
	if len(expectedDeps) > 0 {
		if len(n.DependsOn) != len(expectedDeps) {
			t.Fatalf("node %q deps: got %v, expected %v", nodeID, n.DependsOn, expectedDeps)
		}
		for i, dep := range expectedDeps {
			if n.DependsOn[i] != dep {
				t.Fatalf("node %q dep[%d]: got %q, expected %q", nodeID, i, n.DependsOn[i], dep)
			}
		}
	}
}
