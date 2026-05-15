package harness

// Built-in DBA workflow templates. Each template produces a Plan DAG.
// Templates are designed to be composable — nodes reference MCP tool names
// and the Prompt field provides the instruction for each step.
var builtinTemplates = map[string]*Plan{
	"slow_query_analysis": slowQueryTemplate(),
	"deadlock_analysis":   deadlockTemplate(),
	"disk_space_check":    diskSpaceTemplate(),
	"health_check":        healthCheckTemplate(),
}

func slowQueryTemplate() *Plan {
	return &Plan{
		Name: "慢查询分析",
		Nodes: map[string]*Node{
			"collect": {
				ID:        "collect",
				Name:      "收集慢日志",
				Prompt:    "请查询当前数据库实例最近一小时的慢查询日志，统计总执行次数、平均耗时、最大耗时等关键指标。使用 dba_cloud_get_slow_logs 工具获取数据。",
				Tools:     []string{"dba_cloud_get_slow_logs"},
				OutputKey: "raw_slow_logs",
			},
			"analyze": {
				ID:        "analyze",
				Name:      "分析慢查询模式",
				Prompt:    "分析上一步收集的慢日志数据，找出 TOP 10 耗时最高的查询模式。对每种模式给出：执行频率、平均耗时、扫描行数、建议优化的方向。",
				DependsOn: []string{"collect"},
				Tools:     []string{"dba_cloud_analyze_slow_logs"},
				OutputKey: "analysis_result",
			},
			"report": {
				ID:        "report",
				Name:      "生成优化报告",
				Prompt:    "基于分析结果，生成一份完整的慢查询优化报告。包含：问题概述、TOP 慢查询详情、优化建议、预期收益。使用 read/write 工具生成报告文件。",
				DependsOn: []string{"analyze"},
				Tools:     []string{"read", "write"},
				OutputKey: "report",
			},
			"apply": {
				ID:              "apply",
				Name:            "执行优化（需审批）",
				Description:     "根据报告中的优化建议，执行索引创建或SQL改写操作。此步骤需要人工审批。",
				Prompt:          "请执行上一步报告中列出的优化建议。逐个执行索引创建或SQL改写操作，并验证执行效果。",
				DependsOn:       []string{"report"},
				Tools:           []string{"dba_cloud_execute_optimization"},
				RequireApproval: true,
				OutputKey:       "optimization_result",
			},
		},
		EntryNode: "collect",
	}
}

func deadlockTemplate() *Plan {
	return &Plan{
		Name: "死锁分析",
		Nodes: map[string]*Node{
			"collect": {
				ID:        "collect",
				Name:      "收集死锁信息",
				Prompt:    "请收集当前数据库实例最近的死锁信息。查询 information_schema.INNODB_TRX、SHOW ENGINE INNODB STATUS 等信息，获取死锁发生的时间、涉及的事务和锁信息。",
				OutputKey: "raw_deadlock_info",
			},
			"analyze": {
				ID:        "analyze",
				Name:      "分析锁链",
				Prompt:    "分析上一步收集的死锁信息，识别出锁等待链中的事务依赖关系。标注每个事务：持有的锁、等待的锁、执行的SQL、运行时间。",
				DependsOn: []string{"collect"},
				OutputKey: "lock_chain_analysis",
			},
			"locate": {
				ID:        "locate",
				Name:      "定位问题事务",
				Prompt:    "基于锁链分析结果，定位导致死锁的关键事务。分析这些事务的SQL语句和执行计划，找出可以优化的地方（缺少索引、锁范围过大、事务过长等）。",
				DependsOn: []string{"analyze"},
				OutputKey: "root_cause",
			},
			"report": {
				ID:        "report",
				Name:      "生成分析报告",
				Prompt:    "生成一份完整的死锁分析报告。包含：死锁时间线、锁链图、根因分析、优化建议、修复SQL脚本。",
				DependsOn: []string{"locate"},
				Tools:     []string{"read", "write"},
				OutputKey: "report",
			},
		},
		EntryNode: "collect",
	}
}

func diskSpaceTemplate() *Plan {
	return &Plan{
		Name: "磁盘空间检查",
		Nodes: map[string]*Node{
			"usage": {
				ID:        "usage",
				Name:      "检查磁盘使用率",
				Prompt:    "检查当前数据库实例的磁盘使用率。查询数据目录大小、日志目录大小、临时目录大小。计算整体使用率。",
				OutputKey: "disk_usage",
			},
			"large_files": {
				ID:        "large_files",
				Name:      "查找大文件和大表",
				Prompt:    "基于磁盘使用情况，找出占用空间最大的表（按数据大小排序TOP20）和日志文件。分析哪些可以清理或归档。",
				DependsOn: []string{"usage"},
				OutputKey: "large_objects",
			},
			"growth": {
				ID:        "growth",
				Name:      "分析增长趋势",
				Prompt:    "分析磁盘增长趋势。对比最近7天的使用率变化，预测剩余可用天数。标记需要紧急扩容的实例。",
				DependsOn: []string{"large_files"},
				OutputKey: "growth_analysis",
			},
			"report": {
				ID:        "report",
				Name:      "生成报告",
				Prompt:    "生成磁盘空间检查报告。包含：当前使用率、TOP大表、增长趋势、剩余天数、清理建议、扩容建议。",
				DependsOn: []string{"growth"},
				Tools:     []string{"read", "write"},
				OutputKey: "report",
			},
		},
		EntryNode: "usage",
	}
}

func healthCheckTemplate() *Plan {
	return &Plan{
		Name: "实例健康巡检",
		Nodes: map[string]*Node{
			"connections": {
				ID:        "connections",
				Name:      "检查连接数",
				Prompt:    "检查数据库实例的连接状况。查询当前连接数、最大连接数、活跃连接数、wait_timeout设置。检查是否有异常连接堆积。",
				OutputKey: "connection_status",
			},
			"replication": {
				ID:        "replication",
				Name:      "检查复制状态",
				Prompt:    "检查主从复制状态。查询Seconds_Behind_Master、Slave_IO_Running、Slave_SQL_Running、复制延迟趋势。如有延迟则分析原因。",
				OutputKey: "replication_status",
				Parallel:  true,
			},
			"performance": {
				ID:        "performance",
				Name:      "检查性能指标",
				Prompt:    "检查数据库性能关键指标。QPS、TPS、慢查询率、缓存命中率、InnoDB行锁等待等。标记异常指标。",
				OutputKey: "performance_status",
				Parallel:  true,
			},
			"errors": {
				ID:        "errors",
				Name:      "检查错误日志",
				Prompt:    "检查数据库错误日志中最近24小时的ERROR和WARNING级别的日志。筛选出重复出现的异常模式。",
				OutputKey: "error_log",
				Parallel:  true,
			},
			"report": {
				ID:        "report",
				Name:      "生成巡检报告",
				Prompt:    "基于以上检查结果，生成实例健康巡检报告。包含：总体健康评分、各维度检查结果、发现的问题、风险等级、处理建议。对标记为异常的项目给出明确的修复步骤。",
				DependsOn: []string{"connections", "replication", "performance", "errors"},
				Tools:     []string{"read", "write"},
				OutputKey: "report",
			},
		},
		EntryNode: "connections",
	}
}
