package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// 加载失败原因码：相互可区分，调用方可据此告警或回退。
const (
	CodeFileRead         = "POLICY_FILE_READ_ERROR"
	CodeSyntax           = "POLICY_SYNTAX_ERROR"
	CodeVersionEmpty     = "POLICY_VERSION_EMPTY"
	CodeVersionDowngrade = "POLICY_VERSION_DOWNGRADE"
	CodeVersionSame      = "POLICY_VERSION_REDUNDANT"
	CodeNoRules          = "POLICY_NO_RULES"
	CodeInvalidRule      = "RULE_INVALID"
	CodeInvalidEffect    = "RULE_INVALID_EFFECT"
	CodeInvalidCondition = "RULE_INVALID_CONDITION"
	CodeDuplicateRule    = "RULE_DUPLICATE"
	CodeConflictingRule  = "RULE_CONFLICT"
)

// LoadErrorDetail 定位到具体规则的错误明细。
type LoadErrorDetail struct {
	RuleID  string `json:"rule_id,omitempty"`
	Code    string `json:"code"`
	Message string `json:"message"`
	OtherID string `json:"other_rule_id,omitempty"`
}

// LoadError 是一次策略加载失败的结构化结果。
type LoadError struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Details []LoadErrorDetail `json:"details,omitempty"`
}

func (e *LoadError) Error() string {
	var b strings.Builder
	b.WriteString(e.Code)
	b.WriteString(": ")
	b.WriteString(e.Message)
	for _, d := range e.Details {
		b.WriteString("\n  - [")
		b.WriteString(d.Code)
		b.WriteString("] ")
		if d.RuleID != "" {
			b.WriteString("rule=")
			b.WriteString(d.RuleID)
			b.WriteString(" ")
		}
		b.WriteString(d.Message)
		if d.OtherID != "" {
			b.WriteString(" (other rule=")
			b.WriteString(d.OtherID)
			b.WriteString(")")
		}
	}
	return b.String()
}

func newLoadError(code, msg string, details []LoadErrorDetail) *LoadError {
	return &LoadError{Code: code, Message: msg, Details: details}
}

// NewLoadError 供其他包构造结构化加载错误。
func NewLoadError(code, msg string, details []LoadErrorDetail) *LoadError {
	return newLoadError(code, msg, details)
}

// AsLoadError 从任意 error 中提取结构化加载错误。
func AsLoadError(err error) (*LoadError, bool) {
	if err == nil {
		return nil, false
	}
	var le *LoadError
	if errors.As(err, &le) {
		return le, true
	}
	return nil, false
}

// WrapSyntaxError 把 JSON 解析错误转换为带原因码的加载错误，供 loader 包使用。
func WrapSyntaxError(err error) error {
	if err == nil {
		return nil
	}
	var se *json.SyntaxError
	var ute *json.UnmarshalTypeError
	if errors.As(err, &se) {
		return &LoadError{
			Code:    CodeSyntax,
			Message: fmt.Sprintf("invalid JSON syntax at offset %d: %v", se.Offset, se),
		}
	}
	if errors.As(err, &ute) {
		return &LoadError{
			Code: CodeSyntax,
			Message: fmt.Sprintf("invalid policy field type at %s (offset %d): %v",
				ute.Field, ute.Offset, ute),
		}
	}
	return &LoadError{Code: CodeSyntax, Message: "invalid JSON: " + err.Error()}
}
