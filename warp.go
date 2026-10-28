package main

import (
	"streamion/internal/warp"
)

// RegisterWarp registers a new device with Cloudflare WARP.
func RegisterWarp() (*warp.WarpConfig, error) {
	return warp.Register()
}
