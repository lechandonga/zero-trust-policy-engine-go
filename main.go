package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/lechandonga/zero-trust-policy-engine-go/policy"
)

func main() {
	policyPath := flag.String("policy", "examples/policy.json", "path to policy file")
	requestsPath := flag.String("requests", "", "path to JSONL request file (one request per line)")
	watch := flag.Duration("watch", 0, "if > 0, hot-reload the policy file at this interval")
	flag.Parse()

	engine := &policy.Engine{}
	if err := loadFile(engine, *policyPath); err != nil {
		log.Fatalf("initial policy load failed: %v", err)
	}
	log.Printf("policy loaded: version=%s", engine.Version())

	if *watch > 0 {
		go watchLoop(engine, *policyPath, *watch)
	}

	if *requestsPath == "" {
		log.Println("no -requests file given; engine is running, press Ctrl-C to exit")
		select {}
	}

	f, err := os.Open(*requestsPath)
	if err != nil {
		log.Fatalf("open requests: %v", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		var req policy.Request
		if err := json.Unmarshal([]byte(text), &req); err != nil {
			fmt.Printf("line %d: DENY reason=%s explanation=malformed request JSON: %v\n",
				line, policy.ReasonDeniedInvalidReq, err)
			continue
		}
		d := engine.Evaluate(req)
		out, _ := json.Marshal(d)
		fmt.Printf("line %d: %s\n", line, out)
	}
	if err := sc.Err(); err != nil {
		log.Fatalf("read requests: %v", err)
	}
}

func loadFile(engine *policy.Engine, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return engine.Load(f)
}

func watchLoop(engine *policy.Engine, path string, interval time.Duration) {
	for range time.Tick(interval) {
		if err := loadFile(engine, path); err != nil {
			log.Printf("hot reload rejected, keeping version %q: %v", engine.Version(), err)
			continue
		}
		log.Printf("hot reload applied: version=%s", engine.Version())
	}
}
