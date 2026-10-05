// zte 是零信任决策引擎的本地命令行入口：
//
//	zte validate --policy policy.json
//	zte eval     --policy policy.json --request request.json
//	zte serve    --policy policy.json --watch            (热更新演示)
//
// 退出码：0 允许/加载成功；2 拒绝（业务结论）；1 系统/加载错误。
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lechandonga/zero-trust-policy-engine-go/engine"
	"github.com/lechandonga/zero-trust-policy-engine-go/loader"
	"github.com/lechandonga/zero-trust-policy-engine-go/policy"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		var le *policy.LoadError
		if errors.As(err, &le) {
			fmt.Fprintln(os.Stderr, "policy load failed:")
			fmt.Fprintln(os.Stderr, le.Error())
		} else {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("missing subcommand")
	}
	switch args[0] {
	case "validate":
		return cmdValidate(args[1:])
	case "eval":
		return cmdEval(args[1:])
	case "serve":
		return cmdServe(args[1:])
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `zte - local zero-trust policy engine

usage:
  zte validate --policy <policy.json>
  zte eval     --policy <policy.json> --request <request.json>
  zte serve    --policy <policy.json> [--watch] [--interval 5s]

eval reads JSON access requests from stdin (one JSON object per line when --request omitted);
prints one Decision JSON object per request. Exit code 2 means a deny decision.
`)
}

func policyFlag(fs *flag.FlagSet) *string {
	return fs.String("policy", "", "path to policy JSON file")
}

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	pPath := policyFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	doc, err := loader.LoadFile(*pPath)
	if err != nil {
		return err
	}
	snap, err := engine.Compile(doc)
	if err != nil {
		return err
	}
	fmt.Printf("policy %s OK (%d rules compiled)\n", snap.Version, snap.RuleCount())
	return nil
}

func cmdEval(args []string) error {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	pPath := policyFlag(fs)
	rPath := fs.String("request", "", "path to request JSON file (default: stdin)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	doc, err := loader.LoadFile(*pPath)
	if err != nil {
		return err
	}
	e := engine.New()
	if err := e.Load(doc); err != nil {
		return err
	}
	req, err := readRequest(*rPath)
	if err != nil {
		return err
	}
	dec := e.Evaluate(req)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(dec); err != nil {
		return err
	}
	if !dec.Allowed {
		os.Exit(2)
	}
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	pPath := policyFlag(fs)
	watch := fs.Bool("watch", false, "watch the policy file and hot-reload new versions")
	interval := fs.Duration("interval", 5*time.Second, "poll interval for --watch")
	if err := fs.Parse(args); err != nil {
		return err
	}
	e := engine.New()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *watch {
		rl := loader.NewReloader(e, *pPath, *interval)
		rl.OnResult(func(r loader.ReloadResult) {
			switch {
			case r.Err != nil:
				fmt.Fprintf(os.Stderr, "[reload] FAILED, keeping version %s: %v\n", r.OldVersion, r.Err)
			case r.Applied:
				fmt.Fprintf(os.Stderr, "[reload] %s -> %s\n", r.OldVersion, r.NewVersion)
			}
		})
		readyCh := make(chan loader.ReloadResult, 1)
		go rl.Run(ctx, readyCh)
		first := <-readyCh
		if first.Err != nil {
			return first.Err
		}
	} else if _, err := loader.LoadAndApply(e, *pPath); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "engine ready, policy version=%s; reading JSON requests from stdin, Ctrl-C to exit\n", e.CurrentVersion())
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	enc := json.NewEncoder(os.Stdout)
	for {
		var req policy.Request
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return err
			}
			return nil
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if err := json.Unmarshal(line, &req); err != nil {
			// 无法解析的请求也不能放行：输出确定性的拒绝决策，继续服务后续请求。
			_ = enc.Encode(policy.Decision{
				Allowed:       false,
				ReasonCode:    policy.ReasonDenyMalformed,
				PolicyVersion: e.CurrentVersion(),
				Message:       "request payload is not valid JSON: " + err.Error(),
				EvaluatedAt:   time.Now().UTC().Format(time.RFC3339Nano),
			})
			continue
		}
		if err := enc.Encode(e.Evaluate(&req)); err != nil {
			return err
		}
	}
}

func readRequest(path string) (*policy.Request, error) {
	var f *os.File
	if path == "" {
		f = os.Stdin
	} else {
		var err error
		f, err = os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
	}
	var req policy.Request
	if err := json.NewDecoder(f).Decode(&req); err != nil {
		// 交给引擎的畸形路径处理：返回一个空请求，由引擎给出 DENY_MALFORMED_REQUEST。
		return &policy.Request{}, nil
	}
	return &req, nil
}
