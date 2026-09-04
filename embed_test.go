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
	} {
		if _, err := WebFS.Open(f); err != nil {
			t.Fatalf("缺少嵌入资源 %s: %v", f, err)
		}
	}
}
