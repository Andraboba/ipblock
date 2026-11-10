package ui

import (
	"net/netip"
	"os/exec"
	"time"
)

// Как часто опрашиваются соединения (в macOS это запуск lsof, он небыстрый).
const pollEvery = 1500 * time.Millisecond

// openURL открывает ссылку в браузере по умолчанию.
func openURL(url string) {
	_ = exec.Command("open", url).Start()
}

// В macOS нет простого способа прочитать системный кеш DNS, поэтому адреса остаются без имён.
func dnsNames() map[netip.Addr]string { return nil }
