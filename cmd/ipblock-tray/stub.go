//go:build !(windows || (darwin && cgo))

// Значок для macOS использует системные библиотеки (Cocoa), поэтому собирается
// только на самом Mac. При сборке с другой машины получается эта заглушка.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "ipblock-tray: эта сборка не содержит значка. Соберите на Mac: go build ./cmd/ipblock-tray")
	os.Exit(1)
}
