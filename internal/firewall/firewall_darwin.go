package firewall

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// Стандартный /etc/pf.conf в macOS содержит `anchor "com.apple/*"`,
// поэтому правила в этих под-якорях работают без правки pf.conf.
const (
	anchorMain = "com.apple/ipblock"
	anchorTest = "com.apple/ipblock-selftest"
)

var (
	mu      sync.Mutex
	lastKey string
)

// Lockdown вызывается при запуске сервиса. Загрузка якоря в pf атомарна,
// поэтому отдельной логики не требуется.
func Lockdown(s State) error { return Apply(s) }

// Apply атомарно заменяет правила якоря на соответствующие состоянию s.
// Поле Apps на macOS не используется: встроенного файрвола по программам там нет.
func Apply(s State) error {
	mu.Lock()
	defer mu.Unlock()
	if err := load(anchorMain, s); err != nil {
		return err
	}
	if key := s.Key(); key != lastKey {
		lastKey = key
		killStates(s)
	}
	return nil
}

// Clear убирает все правила ipblock.
func Clear() error {
	mu.Lock()
	defer mu.Unlock()
	lastKey = ""
	_ = flush(anchorTest)
	return flush(anchorMain)
}

// TestApply загружает отдельный якорь для самопроверки, не трогая рабочие правила.
func TestApply(s State) error {
	if err := load(anchorTest, s); err != nil {
		return err
	}
	killStates(s)
	return nil
}

// TestClear убирает якорь самопроверки.
func TestClear() error { return flush(anchorTest) }

// Health сообщает о проблемах, из-за которых правила не будут действовать.
func Health() []string { return nil }

func load(anchor string, s State) error {
	text := RenderPF(s)
	if text == "" {
		return flush(anchor)
	}
	cmd := exec.Command("pfctl", "-a", anchor, "-f", "-")
	cmd.Stdin = strings.NewReader(text)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return ensureEnabled()
}

func flush(anchor string) error {
	if out, err := exec.Command("pfctl", "-a", anchor, "-F", "all").CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// killStates обрывает уже установленные соединения с закрытыми адресами:
// если чужое правило pf завело для них состояние, новые правила на них не подействуют.
func killStates(s State) {
	const limit = 64
	n := 0
	for _, b := range s {
		for _, p := range b.Dst {
			if n++; n > limit {
				return
			}
			src := "0.0.0.0/0"
			if p.Addr().Is6() {
				src = "::/0"
			}
			_ = exec.Command("pfctl", "-k", src, "-k", p.String()).Run()
		}
	}
}

func ensureEnabled() error {
	out, _ := exec.Command("pfctl", "-s", "info").CombinedOutput()
	if strings.Contains(string(out), "Status: Enabled") {
		return nil
	}
	if out, err := exec.Command("pfctl", "-e").CombinedOutput(); err != nil &&
		!strings.Contains(string(out), "already enabled") {
		return fmt.Errorf("pfctl -e: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
