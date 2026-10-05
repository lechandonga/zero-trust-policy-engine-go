package policy

import "sort"

// ConflictReport 汇总规则之间的重复与矛盾。
type ConflictReport struct {
	Duplicates []LoadErrorDetail
	Conflicts  []LoadErrorDetail
}

// HasErrors 报告是否存在任何会阻止加载的问题。
func (r *ConflictReport) HasErrors() bool {
	return len(r.Duplicates) > 0 || len(r.Conflicts) > 0
}

// DetectConflicts 在已通过基础校验的规则集合上检测：
//  1. 选择器完全一致且 effect 相同：重复规则（规则重复，不得静默生效）；
//  2. 选择器完全一致但 effect 不同且 priority 相同：无法以优先级区分的矛盾规则。
//
// 检测仅基于规则内容排序后的规范签名，与文件中的书写顺序无关。
func DetectConflicts(rules []Rule) *ConflictReport {
	groups := make(map[string][]Rule)
	var keyOrder []string
	for i := range rules {
		r := rules[i]
		k := r.canonicalKey()
		if _, ok := groups[k]; !ok {
			keyOrder = append(keyOrder, k)
		}
		groups[k] = append(groups[k], r)
	}
	sort.Strings(keyOrder)

	report := &ConflictReport{}
	for _, k := range keyOrder {
		grp := groups[k]
		if len(grp) < 2 {
			continue
		}
		sort.Slice(grp, func(i, j int) bool { return grp[i].ID < grp[j].ID })
		for i := 0; i < len(grp); i++ {
			for j := i + 1; j < len(grp); j++ {
				a, b := grp[i], grp[j]
				switch {
				case a.Effect == b.Effect:
					report.Duplicates = append(report.Duplicates, LoadErrorDetail{
						RuleID: a.ID, OtherID: b.ID,
						Code:    CodeDuplicateRule,
						Message: "rules have identical selectors, conditions and effect",
					})
				case a.Priority == b.Priority:
					report.Conflicts = append(report.Conflicts, LoadErrorDetail{
						RuleID:  a.ID,
						OtherID: b.ID,
						Code:    CodeConflictingRule,
						Message: "rules have identical selectors but opposing allow/deny effects with equal priority; " +
							"set distinct priorities to resolve deterministically",
					})
				}
			}
		}
	}
	return report
}
