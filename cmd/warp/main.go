package main

import (
	"fmt"
	"os"

	"streamion/internal/warp"
)

func main() {
	cfg, err := warp.Register()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error registering WARP: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(cfg.FormatWireGuardConfig())
}
