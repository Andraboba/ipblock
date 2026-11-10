package firewall

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"golang.org/x/sys/windows/registry"

	"ipblock/internal/netmatch"
)

// Наборы правил различаются именем. Новый набор всегда добавляется ДО удаления
// старого, поэтому в момент смены состояния нет ни мгновения без правил.
const (
	nameBoot = "ipblock-boot" // набор, поставленный при запуске сервиса
	nameA    = "ipblock-a"
	nameB    = "ipblock-b"
	nameTest = "ipblock-selftest"
)

// В одно правило netsh помещаем не больше стольких адресов назначения.
const chunkSize = 100

var (
	mu      sync.Mutex
	current = nameBoot
)

// Lockdown вызывается при запуске сервиса, когда неизвестно, какой набор остался
// от прошлого запуска: сначала ставит s (полный запрет), затем убирает старые наборы.
func Lockdown(s State) error {
	mu.Lock()
	defer mu.Unlock()
	if err := addAll(nameBoot, s); err != nil {
		return err // старые наборы не трогаем: пусть действует то, что есть
	}
	deleteRules(nameA)
	deleteRules(nameB)
	current = nameBoot
	return nil
}

// Apply заменяет действующий набор правил на s без промежутка.
func Apply(s State) error {
	mu.Lock()
	defer mu.Unlock()
	next := nameA
	if current == nameA {
		next = nameB
	}
	deleteRules(next) // остатки неудачной прошлой попытки
	if err := addAll(next, s); err != nil {
		deleteRules(next)
		return err
	}
	deleteRules(current)
	current = next
	return nil
}

// Clear удаляет все правила ipblock.
func Clear() error {
	mu.Lock()
	defer mu.Unlock()
	for _, n := range []string{nameBoot, nameA, nameB, nameTest} {
		deleteRules(n)
	}
	current = nameBoot
	return nil
}

// TestApply ставит отдельный набор для самопроверки, не трогая рабочие правила.
func TestApply(s State) error {
	deleteRules(nameTest)
	return addAll(nameTest, s)
}

// TestClear убирает набор самопроверки.
func TestClear() error {
	deleteRules(nameTest)
	return nil
}

// Health сообщает о проблемах, из-за которых правила не будут действовать.
func Health() []string {
	profiles := []struct{ key, title string }{
		{"DomainProfile", "доменной сети"},
		{"StandardProfile", "частной сети"},
		{"PublicProfile", "общедоступной сети"},
	}
	var off []string
	for _, p := range profiles {
		// Групповая политика важнее локальной настройки.
		v, ok := readDWORD(`SOFTWARE\Policies\Microsoft\WindowsFirewall\` + p.key)
		if !ok {
			v, ok = readDWORD(`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\` + p.key)
		}
		if ok && v == 0 {
			off = append(off, p.title)
		}
	}
	if len(off) == 0 {
		return nil
	}
	return []string{"Брандмауэр Windows выключен для " + strings.Join(off, ", ") +
		" — блокировка адресов и программ там не действует"}
}

func readDWORD(path string) (uint64, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("EnableFirewall")
	return v, err == nil
}

// addAll добавляет все правила состояния под одним именем. Правила создаются
// параллельно: каждое — отдельный запуск netsh, а закрыть доступ нужно быстро.
func addAll(name string, s State) error {
	var rules [][]string
	for _, b := range s {
		var local []string
		if len(b.Allow) > 0 {
			local = []string{"localip=" + strings.Join(prefixStrings(netmatch.Complement(b.Allow)), ",")}
		}
		dst := prefixStrings(b.Dst)
		for len(dst) > 0 {
			n := min(chunkSize, len(dst))
			rules = append(rules, append([]string{"remoteip=" + strings.Join(dst[:n], ",")}, local...))
			dst = dst[n:]
		}
		for _, app := range b.Apps {
			rules = append(rules, append([]string{"program=" + app}, local...))
		}
	}

	errs := make(chan error, len(rules))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, r := range rules {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := addRule(name, r); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	return <-errs // nil, если ошибок не было
}

func addRule(name string, what []string) error {
	args := append([]string{"advfirewall", "firewall", "add", "rule",
		"name=" + name,
		"description=Создано ipblock. Не редактируйте вручную.",
		"dir=out", "action=block", "enable=yes", "profile=any",
	}, what...)
	out, err := exec.Command("netsh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh add rule (%s): %v: %s", shorten(strings.Join(what, " ")), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func deleteRules(name string) {
	// netsh возвращает ошибку и тогда, когда удалять нечего, — это не сбой.
	_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name).Run()
}

func shorten(s string) string {
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}
