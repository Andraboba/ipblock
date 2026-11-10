package engine

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"time"

	"ipblock/internal/detect"
	"ipblock/internal/firewall"
	"ipblock/internal/hosts"
)

// Адреса для самопроверки: общедоступные DNS-серверы, к правилам пользователя отношения не имеют.
var probes = []string{"1.0.0.1:443", "9.9.9.9:443", "8.8.4.4:443"}

// SelfTest проверяет на этой машине, что файрвол на деле закрывает соединения,
// что привязка к локальному адресу работает и что hosts доступен для записи.
// Рабочие правила сервиса не затрагиваются: используется отдельный набор.
func SelfTest(w io.Writer) bool {
	ok := true
	report := func(pass bool, format string, args ...any) {
		mark := "[ OK ]"
		if !pass {
			mark = "[СБОЙ]"
			ok = false
		}
		fmt.Fprintf(w, "  %s %s\n", mark, fmt.Sprintf(format, args...))
	}
	defer firewall.TestClear()
	_ = firewall.TestClear()

	// 1. Исходное состояние: соединение проходит, запоминаем локальный адрес.
	var probe string
	var local netip.Addr
	for _, p := range probes {
		if l, err := dial(p); err == nil {
			probe, local = p, l
			break
		}
	}
	if probe == "" {
		report(false, "нет связи ни с одним проверочным адресом — проверить действие файрвола нельзя")
		return false
	}
	dst := []netip.Prefix{netip.PrefixFrom(netip.MustParseAddrPort(probe).Addr(), 32)}
	report(true, "без правил соединение с %s проходит (локальный адрес %s)", probe, local)

	// expect ставит набор правил и проверяет, проходит ли соединение.
	expect := func(s firewall.State, wantOpen bool, what string) {
		if err := firewall.TestApply(s); err != nil {
			report(false, "%s: правило не создалось: %v", what, err)
			return
		}
		time.Sleep(300 * time.Millisecond)
		_, err := dial(probe)
		switch {
		case wantOpen && err != nil:
			report(false, "%s: соединение должно проходить, но закрыто (%v)", what, err)
		case !wantOpen && err == nil:
			report(false, "%s: соединение должно быть закрыто, но ПРОШЛО", what)
		case wantOpen:
			report(true, "%s: соединение проходит", what)
		default:
			report(true, "%s: соединение закрыто", what)
		}
	}

	// 2–4. Адрес назначения: полный запрет, привязка к своему и к чужому локальному адресу.
	other := netip.MustParseAddr("192.0.2.1")
	expect(firewall.State{{Dst: dst}}, false, "адрес закрыт полностью")
	expect(firewall.State{{Dst: dst, Allow: []netip.Addr{local}}}, true, "адрес открыт только с текущего локального адреса")
	expect(firewall.State{{Dst: dst, Allow: []netip.Addr{other}}}, false, "адрес открыт только с другого локального адреса")

	// Несколько сетей сразу (например VPN и Wi-Fi). Это случай «VPN выключился»:
	// доступ, открытый для адреса одной сети, должен быть закрыт для остальных.
	_ = firewall.TestClear()
	time.Sleep(300 * time.Millisecond)
	var nets []netip.Addr
	if locals, err := detect.LocalIPs(); err == nil {
		for _, l := range locals {
			if l.Is4() && dialFrom(l, probe) == nil {
				nets = append(nets, l)
			}
		}
	}
	if len(nets) < 2 {
		fmt.Fprintln(w, "  [ -- ] выход в интернет сейчас только через одну сеть — проверка «открыто для одной сети, закрыто для другой» пропущена")
	}
	for i, allowed := range nets {
		if len(nets) < 2 || i >= 3 {
			break
		}
		if err := firewall.TestApply(firewall.State{{Dst: dst, Allow: []netip.Addr{allowed}}}); err != nil {
			report(false, "доступ открыт только для сети %s: правило не создалось: %v", allowed, err)
			continue
		}
		time.Sleep(300 * time.Millisecond)
		for _, from := range nets {
			err := dialFrom(from, probe)
			switch {
			case from == allowed && err != nil:
				report(false, "доступ открыт только для сети %s: через неё соединение должно проходить, но закрыто (%v)", allowed, err)
			case from == allowed:
				report(true, "доступ открыт только для сети %s: через неё соединение проходит", allowed)
			case err == nil:
				report(false, "доступ открыт только для сети %s: через сеть %s соединение должно быть закрыто, но ПРОШЛО", allowed, from)
			default:
				report(true, "доступ открыт только для сети %s: через сеть %s соединение закрыто", allowed, from)
			}
		}
	}

	// 5. Программа (только Windows): закрываем сеть самой этой программе.
	if runtime.GOOS == "windows" {
		if exe, err := os.Executable(); err == nil {
			expect(firewall.State{{Apps: []string{exe}}}, false, "программе закрыта сеть")
			expect(firewall.State{{Apps: []string{exe}, Allow: []netip.Addr{local}}}, true, "программе сеть открыта только с текущего локального адреса")
			expect(firewall.State{{Apps: []string{exe}, Allow: []netip.Addr{other}}}, false, "программе сеть открыта только с другого локального адреса")
		}
	}

	// 6. После снятия правил соединение снова проходит.
	if err := firewall.TestClear(); err != nil {
		report(false, "не удалось убрать проверочные правила: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := dial(probe); err != nil {
		report(false, "после снятия правил соединение не восстановилось: %v", err)
	} else {
		report(true, "после снятия правил соединение снова проходит")
	}

	// 7. Файл hosts доступен для записи.
	if f, err := os.OpenFile(hosts.Path(), os.O_WRONLY|os.O_APPEND, 0); err != nil {
		report(false, "файл hosts недоступен для записи: %v", err)
	} else {
		f.Close()
		report(true, "файл hosts доступен для записи (%s)", hosts.Path())
	}

	// Это не сбой механизма, а настройка системы: показываем отдельно от результата проверки.
	for _, warn := range firewall.Health() {
		fmt.Fprintf(w, "  [ !! ] %s\n", warn)
	}
	return ok
}

// dialFrom устанавливает TCP-соединение с заданного локального адреса, то есть через его сеть.
func dialFrom(local netip.Addr, addr string) error {
	d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: local.AsSlice()}}
	c, err := d.Dial("tcp4", addr)
	if err != nil {
		return err
	}
	return c.Close()
}

// dial устанавливает TCP-соединение и возвращает локальный адрес, с которого оно ушло.
func dial(addr string) (netip.Addr, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	c, err := d.Dial("tcp4", addr)
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	ta, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, fmt.Errorf("неизвестный тип адреса %T", c.LocalAddr())
	}
	return ta.AddrPort().Addr().Unmap(), nil
}
