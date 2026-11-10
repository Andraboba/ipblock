// Package service устанавливает ipblock как системный сервис
// (служба Windows / LaunchDaemon в macOS), ставит значок в автозапуск
// и запускает основной цикл сервиса.
package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Name — имя службы Windows.
const Name = "ipblock"

// selfDir — папка, из которой запущена текущая программа.
func selfDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Dir(exe), nil
}

// copyFile копирует src в dst (если это не один и тот же файл).
func copyFile(src, dst string) error {
	if strings.EqualFold(filepath.Clean(src), filepath.Clean(dst)) {
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		return fmt.Errorf("не удалось скопировать программу в %s: %w", dst, err)
	}
	return nil
}

// copySelf копирует текущий исполняемый файл в dst.
func copySelf(dst string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return copyFile(exe, dst)
}

// traySource ищет программу значка: рядом с текущей программой либо уже установленную.
// Пустая строка — значка нет (например, сборка для Mac сделана на другой машине).
func traySource(name string) string {
	if dir, err := selfDir(); err == nil {
		if p := filepath.Join(dir, name); isFile(p) {
			return p
		}
	}
	if p := TrayBinaryPath(); isFile(p) {
		return p
	}
	return ""
}

func isFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}
