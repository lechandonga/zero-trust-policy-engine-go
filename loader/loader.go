// Package loader 负责从本地文件读取并解析策略文档。
package loader

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/lechandonga/zero-trust-policy-engine-go/engine"
	"github.com/lechandonga/zero-trust-policy-engine-go/policy"
)

// LoadFile 从本地文件读取、解析策略文档。
// 读文件失败、JSON 语法错误、字段类型错误均返回带原因码的 *policy.LoadError。
func LoadFile(path string) (*policy.Document, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, policy.NewLoadError(policy.CodeFileRead,
			fmt.Sprintf("cannot read policy file %q: %v", path, err), nil)
	}
	return Parse(raw)
}

// Parse 解析 JSON 字节为策略文档（不做跨规则校验；编译时还会再校验）。
func Parse(raw []byte) (*policy.Document, error) {
	if len(raw) == 0 {
		return nil, policy.NewLoadError(policy.CodeSyntax, "policy file is empty", nil)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc policy.Document
	if err := dec.Decode(&doc); err != nil {
		return nil, policy.WrapSyntaxError(err)
	}
	// 不允许同一文件中串联多个 JSON 对象。
	if dec.More() {
		return nil, policy.NewLoadError(policy.CodeSyntax,
			"policy file must contain exactly one JSON document", nil)
	}
	return &doc, nil
}

// LoadAndApply 读取文件并把新版本原子发布到引擎；任何一步失败都保留旧版本。
func LoadAndApply(e *engine.Engine, path string) (loadedVersion string, err error) {
	doc, err := LoadFile(path)
	if err != nil {
		return "", err
	}
	if err := e.Load(doc); err != nil {
		return "", err
	}
	return doc.Version, nil
}
