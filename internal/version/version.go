// Package version 保存应用的版本与许可信息，供启动日志与管理后台展示。
package version

// Version 为当前版本号。构建时可通过 -ldflags 覆盖：
//
//	go build -ldflags "-X warden/internal/version.Version=1.2.3" ./cmd/warden
var Version = "1.0.1"

// License 为本项目采用的开放源代码许可协议（SPDX 标识）。
const License = "Apache-2.0"

// Name 为项目名称，用于日志与管理后台展示。
const Name = "沃盾 warden"
