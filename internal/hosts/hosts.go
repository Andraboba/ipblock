// Package hosts ведёт собственный блок записей в системном файле hosts.
package hosts

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

const (
	beginMarker = "# >>> ipblock"
	endMarker   = "# <<< ipblock"
	beginLine   = beginMarker + " (управляется автоматически, не редактируйте)"
)

// Path возвращает путь к системному файлу hosts.
func Path() string {
	if runtime.GOOS == "windows" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		return filepath.Join(root, "System32", "drivers", "etc", "hosts")
	}
	return "/etc/hosts"
}

// Render возвращает содержимое hosts, в котором блок ipblock заменён
// на записи для domains. Всё остальное в файле сохраняется как было.
func Render(existing []byte, domains []string) []byte {
	nl := "\n"
	if bytes.Contains(existing, []byte("\r\n")) || (len(existing) == 0 && runtime.GOOS == "windows") {
		nl = "\r\n"
	}

	var kept []string
	inBlock := false
	for _, line := range strings.Split(strings.ReplaceAll(string(existing), "\r\n", "\n"), "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, beginMarker):
			inBlock = true
			continue
		case strings.HasPrefix(t, endMarker):
			inBlock = false
			continue
		}
		if inBlock {
			// Внутри блока выбрасываем только наши записи. Если закрывающий маркер
			// потерялся, чужие строки ниже останутся на месте.
			if t == "" || strings.HasPrefix(t, "0.0.0.0 ") || strings.HasPrefix(t, ":: ") {
				continue
			}
			inBlock = false
		}
		kept = append(kept, line)
	}
	for len(kept) > 0 && strings.TrimSpace(kept[len(kept)-1]) == "" {
		kept = kept[:len(kept)-1]
	}

	var b strings.Builder
	for _, l := range kept {
		b.WriteString(l)
		b.WriteString(nl)
	}

	ds := slices.Clone(domains)
	slices.Sort(ds)
	ds = slices.Compact(ds)
	if len(ds) > 0 {
		if len(kept) > 0 {
			b.WriteString(nl)
		}
		b.WriteString(beginLine + nl)
		for _, d := range ds {
			b.WriteString("0.0.0.0 " + d + nl)
			b.WriteString(":: " + d + nl)
		}
		b.WriteString(endMarker + nl)
	}
	return []byte(b.String())
}

// Apply приводит системный hosts к нужному набору доменов.
// Возвращает true, если файл изменился.
func Apply(domains []string) (bool, error) {
	path := Path()
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	updated := Render(old, domains)
	if bytes.Equal(old, updated) {
		return false, nil
	}
	if err := os.WriteFile(path, updated, 0o644); err != nil {
		return false, err
	}
	return true, nil
}

// FlushDNS сбрасывает системный кеш DNS, чтобы изменения hosts подействовали сразу.
func FlushDNS() {
	switch runtime.GOOS {
	case "windows":
		_ = exec.Command("ipconfig", "/flushdns").Run()
	case "darwin":
		_ = exec.Command("dscacheutil", "-flushcache").Run()
		_ = exec.Command("killall", "-HUP", "mDNSResponder").Run()
	}
}
