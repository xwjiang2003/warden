package assets

import "embed"

// WebFS 嵌入 web/ 目录下的前端静态资源（递归包含子目录，如 vendor/）
//
//go:embed all:web
var WebFS embed.FS

// AdminHTML 嵌入管理后台页面
//
//go:embed web/admin.html
var AdminHTML []byte
