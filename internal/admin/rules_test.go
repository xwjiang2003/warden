package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"warden/internal/config"
	"warden/internal/store"
	"warden/internal/waf"
)

const testBlockAdminRules = `SecRuleEngine On
SecRule REQUEST_URI "@rx ^/admin" "id:1001,phase:1,deny,status:403,msg:'block admin'"
`

// newRulesTestServer 构造注入规则仓库的后台实例：
// holder 已初始化内层 handler（返回 backend-ok），引擎 A 拦 /admin。
func newRulesTestServer(t *testing.T) (*Server, string, *waf.Holder) {
	t.Helper()
	cfg := &config.Config{Listen: ":81", Backend: "http://127.0.0.1:8002"}
	dbPath := filepath.Join(t.TempDir(), "rules.db")
	wr := &cfg.WAFRules
	s := NewServer(config.NewHolder(cfg), "config.json", "sqlite", "", config.AdminConfig{})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-ok"))
	})
	holder := waf.NewHolder()
	holder.Init(next)
	engine, err := waf.NewFromText(testBlockAdminRules, wr)
	if err != nil {
		t.Fatalf("初始引擎构建失败: %v", err)
	}
	holder.SetEngine(engine)

	s.SetRuleRepo("sqlite", dbPath, holder)
	return s, dbPath, holder
}

// TestHandleGetRules 校验规则读取接口字段与来源标注。
func TestHandleGetRules(t *testing.T) {
	s, _, _ := newRulesTestServer(t)
	// 启动时 DB 无规则，GET 时 coraza_conf 为空字符串属预期（未保存过）
	// ——正常启动路径由 main 迁移入库，此处仅校验接口契约。
	m := getJSON(t, s.handleGetRules, "/api/rules")

	for _, k := range []string{"coraza_conf", "waf_rules", "hot_reload", "rules_source"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("/api/rules 缺少字段 %q", k)
		}
	}
	if m["hot_reload"] != true {
		t.Fatalf("hot_reload 应为 true，实际 %v", m["hot_reload"])
	}
	if m["rules_source"] != "db" {
		t.Fatalf("rules_source 应为 db，实际 %v", m["rules_source"])
	}
}

// TestHandlePutRulesHotReload 核心链路：PUT 合法规则 → 落库 + 热切换（无需重启）。
func TestHandlePutRulesHotReload(t *testing.T) {
	s, dbPath, holder := newRulesTestServer(t)

	body := map[string]interface{}{
		"coraza_conf": `SecRuleEngine On
SecRule REQUEST_URI "@rx ^/api" "id:1002,phase:1,deny,status:403,msg:'block api'"
`,
		"waf_rules": config.WAFRulesConfig{ScannerPaths: []string{"phpmyadmin"}},
	}
	payload, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	s.handlePutRules(rec, httptest.NewRequest(http.MethodPut, "/api/rules", bytes.NewReader(payload)))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT 合法规则应 200，实际 %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是 JSON: %v", err)
	}
	if resp["restart_required"] != false {
		t.Fatalf("规则热加载不应要求重启，实际 %v", resp["restart_required"])
	}

	// 落库验证
	conf, ok, err := store.LoadRule("sqlite", dbPath, store.KeyCorazaConf)
	if err != nil || !ok {
		t.Fatalf("规则应已入库（ok=%v err=%v）", ok, err)
	}
	if !strings.Contains(conf, "1002") {
		t.Fatalf("入库规则应为新内容，got: %q", conf)
	}

	// 热切换验证：原引擎拦 /admin，新引擎应拦 /api 且放行 /admin
	handler := holder.Handler()
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/x", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("新规则应拦 /api，实际 %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("新规则应放行 /admin，实际 %d", rec.Code)
	}

	// waf_rules 结构同步更新（供 BuildRules 使用）
	if got := s.cfg.Load().WAFRules.ScannerPaths; len(got) != 1 || got[0] != "phpmyadmin" {
		t.Fatalf("waf_rules 应同步更新: %+v", got)
	}
}

// TestHandlePutRulesInvalid 非法规则必须被拒：400、不落库、不切换（线上引擎不受影响）。
func TestHandlePutRulesInvalid(t *testing.T) {
	s, dbPath, holder := newRulesTestServer(t)

	payload, _ := json.Marshal(map[string]string{
		"coraza_conf": "SecRule REQUEST_URI\n", // 截断指令 → 编译失败
	})
	rec := httptest.NewRecorder()
	s.handlePutRules(rec, httptest.NewRequest(http.MethodPut, "/api/rules", bytes.NewReader(payload)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法规则应 400，实际 %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "编译失败") {
		t.Fatalf("错误信息应说明编译失败: %s", rec.Body.String())
	}

	// 未落库
	if _, ok, _ := store.LoadRule("sqlite", dbPath, store.KeyCorazaConf); ok {
		t.Fatal("非法规则不应落库")
	}
	// 引擎未切换：/admin 仍被原引擎拦截
	rec = httptest.NewRecorder()
	holder.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("非法保存后线上引擎不应变化，/admin 应仍 403，实际 %d", rec.Code)
	}
}

// TestHandlePutRulesEmpty 空 coraza_conf 被拒（规则内容不可清空）。
func TestHandlePutRulesEmpty(t *testing.T) {
	s, _, _ := newRulesTestServer(t)
	payload, _ := json.Marshal(map[string]string{"coraza_conf": ""})
	rec := httptest.NewRecorder()
	s.handlePutRules(rec, httptest.NewRequest(http.MethodPut, "/api/rules", bytes.NewReader(payload)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("空规则应 400，实际 %d", rec.Code)
	}
}

// TestHandlePutRulesNoRepo 未注入规则仓库时 503（防御：主进程启动异常路径）。
func TestHandlePutRulesNoRepo(t *testing.T) {
	s := newTestServer(t)
	rec := httptest.NewRecorder()
	s.handlePutRules(rec, httptest.NewRequest(http.MethodPut, "/api/rules", bytes.NewReader([]byte(`{"coraza_conf":"x"}`))))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("未注入仓库应 503，实际 %d", rec.Code)
	}
}
