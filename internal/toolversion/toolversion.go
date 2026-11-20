// Package toolversion reports the version of a customer tool binary.
package toolversion

import "runtime/debug"

// String returns stamped when a release build set it with -ldflags
// "-X main.version=...". Otherwise it returns the module version that
// go install recorded (for example v2.0.0-beta.5), or "dev" when the build
// recorded none.
func String(stamped string) string {
	if stamped != "" && stamped != "dev" {
		return stamped
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
