package config

import (
	"encoding/json"
	"sync/atomic"
)

// Holder 保存进程内当前生效的配置，支持并发读取与原子替换。
//
// 约定：配置对象经 Store 发布后即视为只读。更新方必须"复制 → 修改 → 替换"
// （copy-on-write），读取方只需 Load 取快照。这样管理后台保存配置、
// 告警循环读取配置、各 API 读取配置之间不再需要共享锁，也不会出现
// `*cfg = newCfg` 这种整 struct 覆盖与并发读相撞的数据竞争。
type Holder struct {
	p atomic.Pointer[Config]
}

// NewHolder 以初始配置创建 Holder。
func NewHolder(c *Config) *Holder {
	h := &Holder{}
	h.p.Store(c)
	return h
}

// Load 返回当前生效配置的快照（调用方不得修改返回对象）。
func (h *Holder) Load() *Config { return h.p.Load() }

// Store 原子替换当前生效配置（调用方之后不得再修改 c）。
func (h *Holder) Store(c *Config) { h.p.Store(c) }

// Clone 深拷贝配置，供 copy-on-write 修改使用（切片/映射不与原对象共享）。
// Config 只含 JSON 可表达的类型，序列化不会失败；兜底返回浅拷贝仅为防御。
func Clone(c *Config) *Config {
	if b, err := json.Marshal(c); err == nil {
		var out Config
		if err := json.Unmarshal(b, &out); err == nil {
			return &out
		}
	}
	cp := *c
	return &cp
}
