package engine

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"ipblock/internal/config"
	"ipblock/internal/detect"
	"ipblock/internal/netmatch"
)

// Snapshot — результат одной проверки.
type Snapshot struct {
	Time        time.Time       `json:"time"`
	IntervalSec int             `json:"interval_sec"`
	Answers     []detect.Answer `json:"answers"` // что ответил каждый сервис определения IP
	LocalIPs    []netip.Addr    `json:"local_ips"`
	PublicErr   string          `json:"public_error,omitempty"`
	Warnings    []string        `json:"warnings,omitempty"`
	Rules       []RuleStatus    `json:"rules"`
}

// Evaluate определяет текущие IP и выносит решение по каждому правилу. Ничего не меняет в системе.
func Evaluate(ctx context.Context, cfg *config.Config) Snapshot {
	return Decide(cfg, Probe(ctx, cfg), localIPs(cfg))
}

// Probe опрашивает все сервисы определения внешнего IP, нужные правилам.
func Probe(ctx context.Context, cfg *config.Config) []detect.Answer {
	services := cfg.AllServices()
	if len(services) == 0 {
		return nil
	}
	out := detect.Ask(ctx, services, false)
	if cfg.NeedsPublicV6() {
		out = append(out, detect.Ask(ctx, services, true)...)
	}
	return out
}

func localIPs(cfg *config.Config) []netip.Addr {
	if !cfg.NeedsLocal() {
		return nil
	}
	ips, _ := detect.LocalIPs()
	return ips
}

// Decide выносит решение по каждому правилу на основе ответов сервисов и локальных адресов.
//
// По внешнему IP правило открывается, только если ВСЕ ответившие сервисы видят
// разрешённый адрес. Когда VPN ведёт трафик к разным сайтам через разные серверы,
// сервисы видят разные адреса, и неизвестно, каким из них воспользуется защищаемый
// сайт — поэтому хватает одного неразрешённого ответа, чтобы доступ остался закрыт.
func Decide(cfg *config.Config, answers []detect.Answer, locals []netip.Addr) Snapshot {
	snap := Snapshot{
		Time: time.Now(), IntervalSec: int(cfg.CheckInterval.Seconds()),
		Answers: answers, LocalIPs: locals,
	}
	if len(cfg.AllServices()) > 0 {
		answered := false
		firstErr := ""
		for _, a := range answers {
			if a.OK() && !a.Stale {
				answered = true
			} else if firstErr == "" && a.Err != "" {
				firstErr = a.Host() + ": " + a.Err
			}
		}
		if !answered {
			snap.PublicErr = "не удалось определить внешний IP: ни один сервис не ответил"
			if firstErr != "" {
				snap.PublicErr += " (" + firstErr + ")"
			}
		}
	}

	for _, r := range cfg.Rules {
		st := RuleStatus{Name: r.Name, Source: r.IPSource}
		services := cfg.ServicesFor(r)
		for _, v6 := range []bool{false, true} {
			local, note := decidePublic(r, services, answers, v6)
			st.AllowedLocal = append(st.AllowedLocal, local...)
			if st.Note == "" {
				st.Note = note
			}
		}
		if r.IPSource != config.SourcePublic {
			for _, ip := range locals {
				if matches(r.AllowMatchers, ip) {
					st.AllowedLocal = append(st.AllowedLocal, ip)
				}
			}
		}
		slices.SortFunc(st.AllowedLocal, func(a, b netip.Addr) int { return a.Compare(b) })
		st.AllowedLocal = slices.Compact(st.AllowedLocal)
		st.Allowed = len(st.AllowedLocal) > 0
		snap.Rules = append(snap.Rules, st)
	}
	return snap
}

// decidePublic решает по одному семейству адресов: возвращает локальные адреса, для
// которых доступ открыт, и пояснение, если сервисы разошлись во мнении.
func decidePublic(r config.Rule, services []string, answers []detect.Answer, v6 bool) (local []netip.Addr, note string) {
	var good, bad []detect.Answer
	for _, a := range answers {
		if a.V6 != v6 || !a.OK() || !slices.Contains(services, a.Service) {
			continue
		}
		switch {
		case !matches(r.AllowMatchers, a.Addr):
			bad = append(bad, a)
		case !a.Stale: // устаревший ответ открыть доступ не может
			good = append(good, a)
		}
	}
	if len(bad) > 0 {
		if len(good) > 0 {
			note = "сервисы проверки видят разные адреса: разрешённый " + groupByAddr(good) +
				", но неразрешённый " + groupByAddr(bad)
		}
		return nil, note
	}
	for _, a := range good {
		local = append(local, a.Local)
	}
	return local, ""
}

func matches(ms []netmatch.Matcher, ip netip.Addr) bool {
	return netmatch.Any(ms, []netip.Addr{ip})
}

// groupByAddr собирает ответы по адресам: «203.0.113.7 (icanhazip.com), 198.51.100.4 (api.ipify.org, ifconfig.me)».
func groupByAddr(answers []detect.Answer) string {
	var order []netip.Addr
	hosts := map[netip.Addr][]string{}
	for _, a := range answers {
		if _, known := hosts[a.Addr]; !known {
			order = append(order, a.Addr)
		}
		h := a.Host()
		if a.Stale {
			h += " — недавний ответ"
		}
		hosts[a.Addr] = append(hosts[a.Addr], h)
	}
	parts := make([]string, len(order))
	for i, addr := range order {
		parts[i] = addr.String() + " (" + strings.Join(hosts[addr], ", ") + ")"
	}
	return strings.Join(parts, ", ")
}

// locked возвращает снимок, в котором все правила закрыты.
func locked(cfg *config.Config, note string) Snapshot {
	snap := Snapshot{Time: time.Now(), IntervalSec: int(cfg.CheckInterval.Seconds())}
	for _, r := range cfg.Rules {
		snap.Rules = append(snap.Rules, RuleStatus{Name: r.Name, Source: r.IPSource, Note: note})
	}
	return snap
}

// String — человекочитаемый вид для команд check и status.
func (s Snapshot) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Проверка: %s\n", s.Time.Format("2006-01-02 15:04:05"))

	// Внешние адреса: по строке на адрес, с перечнем сервисов, которые его видят.
	var ok []detect.Answer
	for _, a := range s.Answers {
		if a.OK() {
			ok = append(ok, a)
		}
	}
	var order []netip.Addr
	byAddr := map[netip.Addr][]detect.Answer{}
	for _, a := range ok {
		if _, known := byAddr[a.Addr]; !known {
			order = append(order, a.Addr)
		}
		byAddr[a.Addr] = append(byAddr[a.Addr], a)
	}
	for _, addr := range order {
		group := byAddr[addr]
		hosts := make([]string, len(group))
		for i, a := range group {
			hosts[i] = a.Host()
			if a.Stale {
				hosts[i] += " — недавний ответ"
			}
		}
		fmt.Fprintf(&b, "Внешний IP:    %s — так видят: %s (локальный адрес %s)\n",
			addr, strings.Join(hosts, ", "), group[0].Local)
	}
	if len(order) > 1 {
		b.WriteString("               Сервисы видят разные адреса: похоже, VPN ведёт трафик к разным сайтам через разные серверы.\n")
	}
	for _, a := range s.Answers {
		if !a.OK() && a.Err != "" {
			fmt.Fprintf(&b, "Не ответил:    %s — %s\n", a.Host(), a.Err)
		}
	}
	if s.PublicErr != "" {
		fmt.Fprintf(&b, "Внешний IP:    %s\n", s.PublicErr)
	}
	if len(s.LocalIPs) > 0 {
		fmt.Fprintf(&b, "Локальные IP:  %s\n", joinAddrs(s.LocalIPs))
	}
	for _, w := range s.Warnings {
		fmt.Fprintf(&b, "ВНИМАНИЕ: %s\n", w)
	}
	for _, r := range s.Rules {
		verdict := "ЗАКРЫТО"
		if r.Allowed {
			verdict = "открыто"
		}
		fmt.Fprintf(&b, "  %-8s %s (по %s IP)", verdict, r.Name, r.Source)
		if r.Allowed {
			fmt.Fprintf(&b, " — только с локального адреса %s", joinAddrs(r.AllowedLocal))
		}
		if r.Note != "" {
			fmt.Fprintf(&b, " — %s", r.Note)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// PublicAddrs — внешние адреса одной строкой, без повторов.
func (s Snapshot) PublicAddrs() string {
	var out []string
	for _, a := range s.Answers {
		if a.OK() && !a.Stale && !slices.Contains(out, a.Addr.String()) {
			out = append(out, a.Addr.String())
		}
	}
	return strings.Join(out, ", ")
}
