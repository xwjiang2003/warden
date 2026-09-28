package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type phase struct {
	conc int
	dur  time.Duration
}

var (
	okCount   int64
	errCount  int64
	latSum    int64
	latCnt    int64
	latMax    int64
	codeCount [600]int64
)

var start = time.Now()

func main() {
	url := flag.String("url", "http://127.0.0.1:81/", "target url")
	sched := flag.String("sched", "32:15,256:15,1000:20,2000:20", "conc:seconds,...")
	ua := flag.String("ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36", "user agent")
	admin := flag.String("admin", "http://127.0.0.1:9090", "admin base")
	backend := flag.String("backend", "http://127.0.0.1:8002", "backend base")
	referer := flag.String("referer", "http://127.0.0.1/", "referer")
	flag.Parse()

	var phases []phase
	for _, s := range strings.Split(*sched, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		kv := strings.SplitN(s, ":", 2)
		c, err := strconv.Atoi(kv[0])
		if err != nil {
			log.Fatalf("bad sched %q", s)
		}
		d := 15
		if len(kv) == 2 {
			if v, err := strconv.Atoi(kv[1]); err == nil {
				d = v
			}
		}
		phases = append(phases, phase{conc: c, dur: time.Duration(d) * time.Second})
	}

	mon := &http.Client{Timeout: 3 * time.Second}
	totals := map[string]int64{}

	getJSON := func(path string) map[string]interface{} {
		resp, err := mon.Get(*admin + path)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()
		var m map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
			return nil
		}
		return m
	}
	getIntURL := func(u string) int64 {
		resp, err := mon.Get(u)
		if err != nil {
			return -1
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		if err != nil {
			return -1
		}
		return v
	}
	delta := func(key string, cur int64) int64 {
		if cur < 0 {
			return -1
		}
		d := cur - totals[key]
		totals[key] = cur
		return d
	}

	tr := &http.Transport{
		MaxIdleConns:        4000,
		MaxIdleConnsPerHost: 4000,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
	}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	ticker := time.NewTicker(time.Second)
	done := make(chan struct{})
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				el := time.Since(start).Seconds()
				m := getJSON("/api/metrics")
				num := func(k string) int64 {
					if m == nil {
						return -1
					}
					if v, ok := m[k].(float64); ok {
						return int64(v)
					}
					return -1
				}
				req := delta("total_requests", num("total_requests"))
				rl := delta("rate_limit_blocked", num("rate_limit_blocked"))
				ccb := delta("cc_blocked", num("cc_blocked"))
				chal := delta("cc_challenged", num("cc_challenged"))
				drop := delta("conn_limit_dropped", num("conn_limit_dropped"))
				wafb := delta("waf_blocked", num("waf_blocked"))
				st := getJSON("/api/stats")
				gor, cpu := int64(-1), float64(-1)
				if st != nil {
					if v, ok := st["num_goroutine"].(float64); ok {
						gor = int64(v)
					}
					if v, ok := st["cpu_percent"].(float64); ok {
						cpu = v
					}
				}
				be := delta("backend", getIntURL(*backend+"/__count"))

				ok := atomic.SwapInt64(&okCount, 0)
				ec := atomic.SwapInt64(&errCount, 0)
				ls := atomic.SwapInt64(&latSum, 0)
				lc := atomic.SwapInt64(&latCnt, 0)
				lm := atomic.SwapInt64(&latMax, 0)
				avgMs, maxMs := int64(-1), int64(-1)
				if lc > 0 {
					avgMs = ls / lc / 1000
					maxMs = lm / 1000
				}
				passed := req - rl - ccb - chal - drop - wafb
				fmt.Fprintf(os.Stdout,
					"t=%4.0fs gor=%-6d entry=%6d ok200=%-6d err=%-5d avg_ms=%-6d max_ms=%-7d pass=%-6d be=%-6d rl=%-6d waf=%-5d cc=%-5d chal=%-5d drop=%-5d cpu=%.0f\n",
					el, gor, req, ok, ec, avgMs, maxMs, passed, be, rl, wafb, ccb, chal, drop, cpu)
			}
		}
	}()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for _, p := range phases {
		fmt.Printf("=== phase conc=%d dur=%s ===\n", p.conc, p.dur)
		for i := 0; i < p.conc; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					req, err := http.NewRequest(http.MethodGet, *url, nil)
					if err != nil {
						return
					}
					req.Header.Set("User-Agent", *ua)
					req.Header.Set("Referer", *referer)
					req.Header.Set("Accept", "text/html,application/xhtml+xml")
					t0 := time.Now()
					resp, err := client.Do(req)
					d := time.Since(t0).Nanoseconds()
					if err != nil {
						atomic.AddInt64(&errCount, 1)
						continue
					}
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					atomic.AddInt64(&latSum, d)
					atomic.AddInt64(&latCnt, 1)
					for {
						old := atomic.LoadInt64(&latMax)
						if d <= old || atomic.CompareAndSwapInt64(&latMax, old, d) {
							break
						}
					}
					if resp.StatusCode >= 0 && resp.StatusCode < 600 {
						atomic.AddInt64(&codeCount[resp.StatusCode], 1)
					}
				}
			}()
		}
		time.Sleep(p.dur)
	}
	close(stop)
	wg.Wait()
	close(done)
	fmt.Println("=== final status codes ===")
	for i, c := range codeCount {
		if c > 0 {
			fmt.Printf("  %d: %d\n", i, c)
		}
	}
}
