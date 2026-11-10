package netmatch

import (
	"net/netip"
	"testing"
)

func TestMatchers(t *testing.T) {
	cases := []struct {
		pattern string
		ip      string
		want    bool
	}{
		{"203.0.113.17", "203.0.113.17", true},
		{"203.0.113.17", "203.0.113.18", false},
		{"203.0.113.0/24", "203.0.113.200", true},
		{"203.0.113.0/24", "203.0.114.1", false},
		{"203.0.113.5/24", "203.0.113.1", true}, // хост-биты маскируются
		{"2001:db8::/32", "2001:db8:1::1", true},
		{"2001:db8::/32", "2001:db9::1", false},
		{"10.0.0.10-10.0.0.20", "10.0.0.15", true},
		{"10.0.0.10-10.0.0.20", "10.0.0.21", false},
		{"10.0.0.20-10.0.0.10", "10.0.0.10", true}, // перевёрнутый диапазон
		{"10.1.*.*", "10.1.250.3", true},
		{"10.1.*.*", "10.2.0.1", false},
		{"192.168.1?.*", "192.168.15.4", true},
		{"192.168.1?.*", "192.168.150.4", false},
		{"10.*.*.*", "2001:db8::1", false},
		{"203.0.113.0/24", "::ffff:203.0.113.9", true}, // IPv4-mapped
	}
	for _, c := range cases {
		m, err := Parse(c.pattern)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.pattern, err)
		}
		if got := m.Contains(netip.MustParseAddr(c.ip)); got != c.want {
			t.Errorf("%q contains %q = %v, want %v", c.pattern, c.ip, got, c.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, s := range []string{"", "10.1.*", "abc", "10.0.0.1-2001:db8::1", "10.0.0.0/33", "10.a.*.*"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) должен вернуть ошибку", s)
		}
	}
}

func TestPrefixes(t *testing.T) {
	got, err := Prefixes("10.0.0.10-10.0.0.20")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.10/31", "10.0.0.12/30", "10.0.0.16/30", "10.0.0.20/32"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("[%d] got %s, want %s", i, got[i], want[i])
		}
	}
	if p, _ := Prefixes("0.0.0.0-255.255.255.255"); len(p) != 1 || p[0].String() != "0.0.0.0/0" {
		t.Errorf("полный диапазон: %v", p)
	}
	if p, _ := Prefixes("8.8.8.8"); len(p) != 1 || p[0].String() != "8.8.8.8/32" {
		t.Errorf("один адрес: %v", p)
	}
	if _, err := Prefixes("10.1.*.*"); err == nil {
		t.Error("шаблон со звёздочкой не должен превращаться в префиксы")
	}
}

func TestComplement(t *testing.T) {
	covered := func(ps []netip.Prefix, ip string) bool {
		a := netip.MustParseAddr(ip)
		for _, p := range ps {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}

	// Без разрешённых адресов закрыто всё, и нет ни одного /0.
	all := Complement(nil)
	if len(all) != 4 {
		t.Fatalf("ожидались 4 половины, получено %v", all)
	}
	for _, p := range all {
		if p.Bits() == 0 {
			t.Errorf("префикс нулевой длины: %v", p)
		}
	}
	for _, ip := range []string{"0.0.0.0", "127.255.255.255", "128.0.0.0", "255.255.255.255", "::", "7fff::1", "8000::", "ffff::1"} {
		if !covered(all, ip) {
			t.Errorf("%s не покрыт полным запретом", ip)
		}
	}

	// Один разрешённый IPv4: не покрыт только он; весь IPv6 покрыт.
	one := Complement([]netip.Addr{netip.MustParseAddr("192.168.1.50")})
	if covered(one, "192.168.1.50") {
		t.Error("разрешённый адрес попал в запрет")
	}
	for _, ip := range []string{"192.168.1.49", "192.168.1.51", "0.0.0.0", "255.255.255.255", "10.0.0.1", "::1", "2001:db8::1"} {
		if !covered(one, ip) {
			t.Errorf("%s должен быть в запрете", ip)
		}
	}

	// Крайние адреса и оба семейства сразу.
	edge := Complement([]netip.Addr{
		netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("255.255.255.255"),
		netip.MustParseAddr("2001:db8::5"), netip.MustParseAddr("::ffff:10.0.0.7"),
	})
	for _, ip := range []string{"0.0.0.0", "255.255.255.255", "2001:db8::5", "10.0.0.7"} {
		if covered(edge, ip) {
			t.Errorf("%s разрешён, но попал в запрет", ip)
		}
	}
	for _, ip := range []string{"0.0.0.1", "255.255.255.254", "2001:db8::4", "2001:db8::6", "10.0.0.6", "10.0.0.8"} {
		if !covered(edge, ip) {
			t.Errorf("%s должен быть в запрете", ip)
		}
	}
}
