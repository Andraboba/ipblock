//go:build darwin && cgo

package main

import (
	"os/exec"

	"ipblock/internal/icon"
)

var icons = map[icon.Kind][]byte{}

func iconBytes(k icon.Kind) []byte {
	if icons[k] == nil {
		icons[k] = icon.PNG(k, 36) // строка меню показывает 16–18 pt, 36 px — чётко на Retina
	}
	return icons[k]
}

// Единственность экземпляра обеспечивает launchd: агент с одной меткой запускается один раз.
func singleInstance() bool { return true }

// На macOS путь к настройкам передаётся в аргументах LaunchAgent.
func installedConfigPath() string { return "" }

// Файл настроек при `ipblock init` получает группу admin, поэтому
// администратор компьютера может править его в обычном редакторе.
func openConfig(path string) { _ = exec.Command("open", "-t", path).Start() }

func openLog(path string) { _ = exec.Command("open", "-t", path).Start() }

// openPanel запускает панель управления от имени текущего пользователя:
// файл настроек доступен на запись группе admin, а свои процессы видны и так.
func openPanel(cfgPath string) {
	_ = exec.Command(mainBinary("ipblock"), "ui", "-config", cfgPath).Start()
}
