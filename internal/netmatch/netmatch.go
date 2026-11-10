// Package netmatch разбирает «маски» адресов и проверяет попадание IP в них.
//
// Поддерживаемые форматы:
//
//	203.0.113.17              — один адрес (IPv4 или IPv6)
//	203.0.113.0/24            — CIDR
//	2001:db8::/32             — CIDR IPv6
//	203.0.113.10-203.0.113.50 — диапазон
//	203.0.*.*  / 10.1.2?.*    — шаблон по октетам (* — любое значение, ? — любая цифра)
package netmatch

import (
	"fmt"
	"math/big"
	"net/netip"
	"path"
	"slices"
	"strings"
)

// Matcher проверяет, попадает ли адрес в шаблон.
type Matcher interface {
	Contains(ip netip.Addr) bool
	String() string
}

// Parse разбирает один шаблон.
func Parse(s string) (Matcher, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("пустой шаблон адреса")
	}

	if strings.ContainsAny(s, "*?") {
		return parseWildcard(s)
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("неверный CIDR %q: %w", s, err)
		}
		return prefixMatcher{p.Masked()}, nil
	}
	if from, to, ok := strings.Cut(s, "-"); ok {
		a, err1 := netip.ParseAddr(strings.TrimSpace(from))
		b, err2 := netip.ParseAddr(strings.TrimSpace(to))
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("неверный диапазон %q", s)
		}
		a, b = a.Unmap(), b.Unmap()
		if a.Is4() != b.Is4() {
			return nil, fmt.Errorf("диапазон %q смешивает IPv4 и IPv6", s)
		}
		if b.Less(a) {
			a, b = b, a
		}
		return rangeMatcher{a, b}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return nil, fmt.Errorf("неверный адрес %q: %w", s, err)
	}
	a = a.Unmap()
	return prefixMatcher{netip.PrefixFrom(a, a.BitLen())}, nil
}

// ParseList разбирает список шаблонов.
func ParseList(list []string) ([]Matcher, error) {
	out := make([]Matcher, 0, len(list))
	for _, s := range list {
		m, err := Parse(s)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// Any возвращает true, если хотя бы один адрес попадает хотя бы в один шаблон.
func Any(ms []Matcher, ips []netip.Addr) bool {
	for _, ip := range ips {
		for _, m := range ms {
			if m.Contains(ip) {
				return true
			}
		}
	}
	return false
}

type prefixMatcher struct{ p netip.Prefix }

func (m prefixMatcher) Contains(ip netip.Addr) bool { return m.p.Contains(ip.Unmap()) }
func (m prefixMatcher) String() string              { return m.p.String() }

type rangeMatcher struct{ from, to netip.Addr }

func (m rangeMatcher) Contains(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Is4() != m.from.Is4() {
		return false
	}
	return !ip.Less(m.from) && !m.to.Less(ip)
}
func (m rangeMatcher) String() string { return m.from.String() + "-" + m.to.String() }

type wildcardMatcher struct {
	raw    string
	octets [4]string
}

func parseWildcard(s string) (Matcher, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("шаблон %q должен состоять из 4 октетов (например 10.1.*.*)", s)
	}
	var w wildcardMatcher
	w.raw = s
	for i, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("пустой октет в шаблоне %q", s)
		}
		for _, r := range p {
			if !(r >= '0' && r <= '9') && r != '*' && r != '?' {
				return nil, fmt.Errorf("недопустимый символ %q в шаблоне %q", r, s)
			}
		}
		w.octets[i] = p
	}
	return w, nil
}

func (m wildcardMatcher) Contains(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.Is4() {
		return false
	}
	b := ip.As4()
	for i, pat := range m.octets {
		ok, _ := path.Match(pat, fmt.Sprint(b[i]))
		if !ok {
			return false
		}
	}
	return true
}
func (m wildcardMatcher) String() string { return m.raw }

// Prefixes превращает IP, CIDR или диапазон в список префиксов (для файрвола).
func Prefixes(s string) ([]netip.Prefix, error) {
	m, err := Parse(s)
	if err != nil {
		return nil, err
	}
	switch v := m.(type) {
	case prefixMatcher:
		return []netip.Prefix{v.p}, nil
	case rangeMatcher:
		return rangeToPrefixes(v.from, v.to), nil
	}
	return nil, fmt.Errorf("шаблон %q нельзя использовать как адрес назначения — укажите IP, CIDR или диапазон", s)
}

func rangeToPrefixes(from, to netip.Addr) []netip.Prefix {
	bits := from.BitLen()
	a := new(big.Int).SetBytes(from.AsSlice())
	b := new(big.Int).SetBytes(to.AsSlice())
	one := big.NewInt(1)
	var out []netip.Prefix
	for a.Cmp(b) <= 0 {
		// Самый большой блок, выровненный по a и не выходящий за b.
		size := bits
		if a.Sign() != 0 {
			size = min(int(a.TrailingZeroBits()), bits)
		}
		for size > 0 {
			end := new(big.Int).Lsh(one, uint(size))
			end.Add(end, a).Sub(end, one)
			if end.Cmp(b) <= 0 {
				break
			}
			size--
		}
		buf := make([]byte, bits/8)
		a.FillBytes(buf)
		addr, _ := netip.AddrFromSlice(buf)
		out = append(out, netip.PrefixFrom(addr, bits-size))
		a.Add(a, new(big.Int).Lsh(one, uint(size)))
	}
	return out
}

// Complement возвращает префиксы, покрывающие все адреса IPv4 и IPv6, кроме перечисленных.
// Префиксов нулевой длины в ответе не бывает: всё пространство отдаётся двумя половинами (/1),
// потому что не все файрволы принимают /0.
func Complement(allowed []netip.Addr) []netip.Prefix {
	var v4, v6 []netip.Addr
	for _, a := range allowed {
		a = a.Unmap().WithZone("")
		switch {
		case !a.IsValid():
		case a.Is4():
			v4 = append(v4, a)
		default:
			v6 = append(v6, a)
		}
	}
	out := complementFamily(v4, netip.IPv4Unspecified(), netip.AddrFrom4([4]byte{255, 255, 255, 255}))
	var max6 [16]byte
	for i := range max6 {
		max6[i] = 0xff
	}
	return append(out, complementFamily(v6, netip.IPv6Unspecified(), netip.AddrFrom16(max6))...)
}

func complementFamily(addrs []netip.Addr, first, last netip.Addr) []netip.Prefix {
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	addrs = slices.Compact(addrs)

	var out []netip.Prefix
	cur := first
	for _, a := range addrs {
		if cur.Less(a) {
			out = append(out, rangeToPrefixes(cur, a.Prev())...)
		}
		cur = a.Next()
		if !cur.IsValid() { // a — последний адрес семейства
			return out
		}
	}
	for _, p := range rangeToPrefixes(cur, last) {
		if p.Bits() == 0 {
			half := netip.PrefixFrom(first, 1)
			upper := rangeToPrefixes(netip.PrefixFrom(last, 1).Masked().Addr(), last)
			out = append(out, half)
			out = append(out, upper...)
			continue
		}
		out = append(out, p)
	}
	return out
}
