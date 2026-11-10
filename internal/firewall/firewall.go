// Package firewall закрывает исходящие соединения средствами ОС:
// Windows — правила Брандмауэра Защитника (netsh advfirewall),
// macOS — якорь pf.
//
// Модель — «запрещено, пока не доказано обратное». Для каждого правила конфига
// существует блок: адреса назначения и программы закрыты для всех локальных
// адресов, кроме перечисленных в Allow. Привязка к локальному адресу проверяется
// ядром на каждом соединении, поэтому при переключении на другую сеть (другой
// локальный адрес) доступ пропадает сам, без участия сервиса.
package firewall

import (
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Block — что закрыто для одного правила конфига.
type Block struct {
	Dst  []netip.Prefix // адреса назначения
	Apps []string       // полные пути программ (только Windows)
	// Локальные адреса, с которых доступ подтверждён. Пусто — закрыто полностью.
	Allow []netip.Addr
}

// State — все блоки.
type State []Block

// Normalize сортирует и убирает повторы, чтобы одинаковые состояния давали одинаковый Key.
func (s State) Normalize() {
	for i := range s {
		b := &s[i]
		slices.SortFunc(b.Dst, func(x, y netip.Prefix) int {
			if c := x.Addr().Compare(y.Addr()); c != 0 {
				return c
			}
			return x.Bits() - y.Bits()
		})
		b.Dst = slices.Compact(b.Dst)
		slices.Sort(b.Apps)
		b.Apps = slices.Compact(b.Apps)
		slices.SortFunc(b.Allow, func(x, y netip.Addr) int { return x.Compare(y) })
		b.Allow = slices.Compact(b.Allow)
	}
}

// Key — строка, однозначно описывающая состояние.
func (s State) Key() string {
	var sb strings.Builder
	for _, b := range s {
		sb.WriteString(strings.Join(prefixStrings(b.Dst), ","))
		sb.WriteByte('|')
		sb.WriteString(strings.Join(b.Apps, ","))
		sb.WriteByte('|')
		sb.WriteString(strings.Join(addrStrings(b.Allow), ","))
		sb.WriteByte('\n')
	}
	return sb.String()
}

// Locked возвращает то же состояние без единого разрешённого адреса.
func (s State) Locked() State {
	out := make(State, len(s))
	for i, b := range s {
		out[i] = Block{Dst: b.Dst, Apps: b.Apps}
	}
	return out
}

// Count возвращает число закрытых адресов и программ.
func (s State) Count() (dst, apps int) {
	for _, b := range s {
		dst += len(b.Dst)
		apps += len(b.Apps)
	}
	return
}

// ExpandApp превращает путь из конфига в список исполняемых файлов:
// файл — как есть, папка — все .exe внутри неё (у многих программ сеть
// идёт через вспомогательные процессы из той же папки).
func ExpandApp(path string) []string {
	fi, err := os.Stat(path)
	if err != nil || !fi.IsDir() {
		return []string{path}
	}
	const limit = 300
	var out []string
	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.EqualFold(filepath.Ext(p), ".exe") {
			out = append(out, p)
			if len(out) >= limit {
				return filepath.SkipAll
			}
		}
		return nil
	})
	return out
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

func addrStrings(as []netip.Addr) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.String()
	}
	return out
}

// RenderPF возвращает текст правил pf (macOS) для состояния s: сначала таблицы, затем правила.
// Для блока с разрешёнными адресами закрыто всё, что идёт НЕ с этих локальных адресов.
func RenderPF(s State) string {
	var tables, rules strings.Builder
	for i, b := range s {
		if len(b.Dst) == 0 {
			continue
		}
		fmt.Fprintf(&tables, "table <ipblock_dst_%d> { %s }\n", i, strings.Join(prefixStrings(b.Dst), ", "))
		if len(b.Allow) == 0 {
			fmt.Fprintf(&rules, "block return out quick to <ipblock_dst_%d>\n", i)
			continue
		}
		fmt.Fprintf(&tables, "table <ipblock_src_%d> { %s }\n", i, strings.Join(addrStrings(b.Allow), ", "))
		fmt.Fprintf(&rules, "block return out quick from ! <ipblock_src_%d> to <ipblock_dst_%d>\n", i, i)
	}
	return tables.String() + rules.String()
}
