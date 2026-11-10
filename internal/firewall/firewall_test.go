package firewall

import (
	"net/netip"
	"testing"
)

func TestRenderPF(t *testing.T) {
	s := State{
		{Dst: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::1/128")}},
		{Apps: []string{"/Applications/X.app"}}, // без адресов: в pf попасть не должно
		{Dst: []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32")}, Allow: []netip.Addr{netip.MustParseAddr("10.20.0.5")}},
	}
	want := "table <ipblock_dst_0> { 192.0.2.0/24, 2001:db8::1/128 }\n" +
		"table <ipblock_dst_2> { 198.51.100.7/32 }\n" +
		"table <ipblock_src_2> { 10.20.0.5 }\n" +
		"block return out quick to <ipblock_dst_0>\n" +
		"block return out quick from ! <ipblock_src_2> to <ipblock_dst_2>\n"
	if got := RenderPF(s); got != want {
		t.Errorf("получено:\n%s\nожидалось:\n%s", got, want)
	}
	if RenderPF(State{{Apps: []string{"x"}}}) != "" {
		t.Error("состояние без адресов должно давать пустой набор правил")
	}
}

func TestKeyAndLocked(t *testing.T) {
	a := State{{
		Dst:   []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32"), netip.MustParsePrefix("10.0.0.1/32"), netip.MustParsePrefix("10.0.0.2/32")},
		Apps:  []string{`C:\b.exe`, `C:\a.exe`},
		Allow: []netip.Addr{netip.MustParseAddr("192.168.1.5")},
	}}
	b := State{{
		Dst:   []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32"), netip.MustParsePrefix("10.0.0.2/32")},
		Apps:  []string{`C:\a.exe`, `C:\b.exe`},
		Allow: []netip.Addr{netip.MustParseAddr("192.168.1.5")},
	}}
	a.Normalize()
	b.Normalize()
	if a.Key() != b.Key() {
		t.Errorf("одинаковые состояния дают разные ключи:\n%q\n%q", a.Key(), b.Key())
	}
	l := a.Locked()
	if len(l[0].Allow) != 0 || len(l[0].Dst) != 2 || len(l[0].Apps) != 2 {
		t.Errorf("Locked: %+v", l)
	}
	if l.Key() == a.Key() {
		t.Error("закрытое и открытое состояния не должны совпадать по ключу")
	}
	if len(a[0].Allow) != 1 {
		t.Error("Locked изменил исходное состояние")
	}
}
