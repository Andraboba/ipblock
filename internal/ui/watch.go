package ui

import (
	"context"
	"net/netip"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"ipblock/internal/conns"
	"ipblock/internal/procs"
)

// groupKey объединяет процессы одной программы: у браузеров и почтовых клиентов
// их десятки, а пользователю нужна одна строка.
func groupKey(p procs.Proc) string {
	if p.Path == "" {
		return "name:" + strings.ToLower(p.Name)
	}
	if runtime.GOOS == "darwin" {
		if i := strings.Index(p.Path, ".app/"); i >= 0 {
			return p.Path[:i+4] // весь пакет приложения, вместе со вспомогательными процессами
		}
		return p.Path
	}
	return strings.ToLower(p.Path)
}

// groupPath — путь программы для показа и для записи в настройки.
func groupPath(p procs.Proc) string {
	if runtime.GOOS == "darwin" {
		if i := strings.Index(p.Path, ".app/"); i >= 0 {
			return p.Path[:i+4]
		}
	}
	return p.Path
}

func groupName(p procs.Proc) string {
	if gp := groupPath(p); gp != "" {
		return filepath.Base(gp)
	}
	return p.Name
}

// pidsOf возвращает процессы программы key и всех их потомков.
func pidsOf(list []procs.Proc, key string) map[int]bool {
	pids := map[int]bool{}
	for _, p := range list {
		if groupKey(p) == key {
			pids[p.PID] = true
		}
	}
	for grew := true; grew; {
		grew = false
		for _, p := range list {
			if pids[p.PPID] && !pids[p.PID] && p.PID != p.PPID {
				pids[p.PID] = true
				grew = true
			}
		}
	}
	return pids
}

type connKey struct {
	remote netip.AddrPort
	local  uint16
}

type seen struct {
	ports map[uint16]bool
	conns map[connKey]bool
	first time.Time
	last  time.Time
}

// watcher накапливает адреса, с которыми соединялась одна программа.
type watcher struct {
	key, name, path string
	started         time.Time
	cancel          context.CancelFunc

	mu     sync.Mutex
	active bool
	procs  int
	err    string
	found  map[netip.Addr]*seen
	names  map[netip.Addr]string
}

func startWatch(key, name, path string) *watcher {
	ctx, cancel := context.WithCancel(context.Background())
	w := &watcher{
		key: key, name: name, path: path,
		started: time.Now(), cancel: cancel, active: true,
		found: map[netip.Addr]*seen{}, names: map[netip.Addr]string{},
	}
	go w.poll(ctx)
	go w.resolveNames(ctx)
	return w
}

func (w *watcher) stop() {
	w.cancel()
	w.mu.Lock()
	w.active = false
	w.mu.Unlock()
}

// poll часто опрашивает таблицу соединений: короткие соединения живут доли секунды.
func (w *watcher) poll(ctx context.Context) {
	t := time.NewTicker(pollEvery)
	defer t.Stop()
	var list []procs.Proc
	var listAt time.Time
	for {
		if time.Since(listAt) > 2*time.Second {
			if l, err := procs.List(); err == nil {
				list, listAt = l, time.Now()
			}
		}
		pids := pidsOf(list, w.key)
		cs, err := conns.Snapshot()

		w.mu.Lock()
		w.procs = len(pids)
		w.err = ""
		if err != nil {
			w.err = err.Error()
		}
		now := time.Now()
		for _, c := range cs {
			if !pids[c.PID] {
				continue
			}
			ip := c.Remote.Addr()
			s := w.found[ip]
			if s == nil {
				s = &seen{ports: map[uint16]bool{}, conns: map[connKey]bool{}, first: now}
				w.found[ip] = s
			}
			s.ports[c.Remote.Port()] = true
			s.conns[connKey{c.Remote, c.LocalPort}] = true
			s.last = now
		}
		w.mu.Unlock()

		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// resolveNames подписывает адреса именами сайтов из системного кеша DNS.
// В сеть при этом ничего не уходит.
func (w *watcher) resolveNames(ctx context.Context) {
	for {
		names := dnsNames()
		w.mu.Lock()
		for ip, n := range names {
			if _, known := w.names[ip]; !known {
				w.names[ip] = n
			}
		}
		w.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

type foundView struct {
	IP       string `json:"ip"`
	Ports    []int  `json:"ports"`
	Conns    int    `json:"conns"`
	Name     string `json:"name"`
	FirstSec int    `json:"first_sec"` // через сколько секунд после начала наблюдения замечен
	AgoSec   int    `json:"ago_sec"`   // сколько секунд назад замечен в последний раз
}

type watchView struct {
	Active  bool        `json:"active"`
	Name    string      `json:"name"`
	Path    string      `json:"path"`
	Seconds int         `json:"seconds"`
	Procs   int         `json:"procs"`
	Error   string      `json:"error,omitempty"`
	Items   []foundView `json:"items"`
}

func (w *watcher) view() watchView {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := watchView{
		Active: w.active, Name: w.name, Path: w.path,
		Seconds: int(time.Since(w.started).Seconds()),
		Procs:   w.procs, Error: w.err, Items: []foundView{},
	}
	type row struct {
		foundView
		first time.Time
		ip    netip.Addr
	}
	var rows []row
	for ip, s := range w.found {
		ports := make([]int, 0, len(s.ports))
		for p := range s.ports {
			ports = append(ports, int(p))
		}
		slices.Sort(ports)
		rows = append(rows, row{
			foundView: foundView{
				IP: ip.String(), Ports: ports, Conns: len(s.conns), Name: w.names[ip],
				FirstSec: int(s.first.Sub(w.started).Seconds()),
				AgoSec:   int(time.Since(s.last).Seconds()),
			},
			first: s.first, ip: ip,
		})
	}
	// Новые адреса сверху; при равном времени — по адресу, чтобы строки не прыгали.
	slices.SortFunc(rows, func(a, b row) int {
		if c := b.first.Compare(a.first); c != 0 {
			return c
		}
		return a.ip.Compare(b.ip)
	})
	for _, r := range rows {
		v.Items = append(v.Items, r.foundView)
	}
	return v
}
