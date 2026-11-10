package engine

import (
	"encoding/json"
	"net/netip"
	"os"
	"time"
)

const (
	// Сколько адресов помним на один домен.
	maxLearned = 300
	// Адрес, который не встречался столько времени, забывается.
	learnedTTL = 45 * 24 * time.Hour
	// Как часто сохраняем на диск обновления «видели недавно» (новые адреса — сразу).
	learnedSaveEvery = time.Hour
)

// learned — IP-адреса доменов, увиденные, пока доступ был открыт.
// Хранится на диске: блокировка по ним должна действовать сразу после перезагрузки.
type learned struct {
	path  string
	data  map[string]map[netip.Addr]int64 // домен → адрес → когда видели (unix)
	saved time.Time
}

func loadLearned(path string) *learned {
	l := &learned{path: path, data: map[string]map[netip.Addr]int64{}}
	raw, err := os.ReadFile(path)
	if err != nil {
		return l
	}
	_ = json.Unmarshal(raw, &l.data)
	if l.data == nil {
		l.data = map[string]map[netip.Addr]int64{}
	}
	cutoff := time.Now().Add(-learnedTTL).Unix()
	for d, ips := range l.data {
		for ip, seen := range ips {
			if seen < cutoff {
				delete(ips, ip)
			}
		}
		if len(ips) == 0 {
			delete(l.data, d)
		}
	}
	return l
}

// add запоминает адреса домена. Возвращает true, если появился новый адрес.
func (l *learned) add(domain string, addrs []netip.Addr) bool {
	set := l.data[domain]
	if set == nil {
		set = map[netip.Addr]int64{}
		l.data[domain] = set
	}
	now := time.Now().Unix()
	added := false
	for _, a := range addrs {
		a = a.Unmap().WithZone("")
		// 0.0.0.0 и :: — это наш собственный блок в hosts, а не адрес сайта.
		if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() {
			continue
		}
		if _, known := set[a]; !known {
			if len(set) >= maxLearned {
				continue
			}
			added = true
		}
		set[a] = now
	}
	return added
}

// prefixes возвращает запомненные адреса домена.
func (l *learned) prefixes(domain string) []netip.Prefix {
	set := l.data[domain]
	out := make([]netip.Prefix, 0, len(set))
	for a := range set {
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out
}

func (l *learned) save(force bool) {
	if !force && time.Since(l.saved) < learnedSaveEvery {
		return
	}
	l.saved = time.Now()
	if raw, err := json.Marshal(l.data); err == nil {
		_ = os.WriteFile(l.path, raw, 0o644)
	}
}
