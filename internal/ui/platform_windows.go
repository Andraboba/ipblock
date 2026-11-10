package ui

import (
	"net/netip"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// Как часто опрашивается таблица соединений (в Windows это быстрый системный вызов).
const pollEvery = 300 * time.Millisecond

const createNoWindow = 0x08000000

// openURL открывает ссылку в браузере по умолчанию — тем же системным способом,
// каким открываются ссылки из других программ.
func openURL(url string) {
	_ = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url).Start()
}

// dnsNames читает системный кеш DNS: какие имена недавно превращались в какие адреса.
// Это локальные данные Windows, в сеть ничего не уходит.
func dnsNames() map[netip.Addr]string {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`Get-DnsClientCache | ForEach-Object { $_.Entry + "|" + $_.Data }`)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	names := map[netip.Addr]string{}
	for _, line := range strings.Split(string(out), "\n") {
		entry, data, ok := strings.Cut(strings.TrimSpace(line), "|")
		if !ok || entry == "" {
			continue
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(data))
		if err != nil {
			continue // запись не об адресе (например, CNAME)
		}
		if _, known := names[ip.Unmap()]; !known {
			names[ip.Unmap()] = entry
		}
	}
	return names
}
