package assets

import "testing"

// TestVendorAssetsEmbedded 保证前端依赖的静态资源在构建时被嵌入，避免页面白屏。
func TestVendorAssetsEmbedded(t *testing.T) {
	for _, f := range []string{
		"web/admin.html",
		"web/vendor/vue.global.prod.js",
		"web/vendor/vue-router.global.prod.js",
		"web/vendor/element-plus.full.min.js",
		"web/vendor/element-plus.index.css",
		"web/vendor/axios.min.js",
		"web/vendor/echarts.min.js",
	} {
		if _, err := WebFS.Open(f); err != nil {
			t.Fatalf("缺少嵌入资源 %s: %v", f, err)
		}
	}
}

// TestLegalFilesEmbedded 保证开源许可与第三方声明被嵌入，
// 管理后台页脚才能在线查看（Apache-2.0 要求分发时随附许可与声明）。
func TestLegalFilesEmbedded(t *testing.T) {
	for _, f := range []string{"LICENSE", "NOTICE"} {
		if _, err := LegalFS.Open(f); err != nil {
			t.Fatalf("缺少嵌入文件 %s: %v", f, err)
		}
	}
}
