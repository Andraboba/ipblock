// Package ui — панель управления ipblock, открывающаяся в браузере.
//
// Панель работает только на этом компьютере (127.0.0.1) и только пока запущена
// команда `ipblock ui`. Каждый запуск получает случайный ключ: без него сервер
// не отдаёт ни страницу, ни данные, поэтому посторонний сайт или программа,
// не знающие ключа, к панели обратиться не могут.
package ui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"ipblock/internal/config"
	"ipblock/internal/conns"
	"ipblock/internal/engine"
	"ipblock/internal/procs"
)

//go:embed page.html
var page string

const (
	// Панель закрывается сама, если страница перестала отвечать (вкладку закрыли).
	idleAfterOpen = 45 * time.Second
	// Сколько ждём, пока страницу откроют в первый раз.
	idleBeforeOpen = 5 * time.Minute
)

type server struct {
	cfgPath string
	token   string
	host    string
	quit    func()
	out     io.Writer

	mu       sync.Mutex
	watch    *watcher
	lastPing time.Time
	opened   bool
}

// Options — параметры запуска панели.
type Options struct {
	ConfigPath  string
	OpenBrowser bool
	Out         io.Writer
	// Listen и Token задаёт значок, когда запускает панель сам: ему нужно заранее
	// знать ссылку, чтобы открыть её в браузере с обычными правами пользователя.
	// Пустые значения — свободный порт и случайный ключ.
	Listen string
	Token  string
}

// Run запускает панель и работает, пока её не закроют или не отменят ctx.
func Run(ctx context.Context, o Options) error {
	cfgPath, out := o.ConfigPath, o.Out
	listen := o.Listen
	if listen == "" {
		listen = "127.0.0.1:0"
	}
	// Панель доступна только с этого компьютера: другой адрес не принимаем.
	if ap, err := netip.ParseAddrPort(listen); err != nil || !ap.Addr().IsLoopback() {
		return fmt.Errorf("панель можно открыть только на адресе этого компьютера (127.0.0.1), получено %q", listen)
	}
	token := o.Token
	if token == "" {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		token = hex.EncodeToString(raw)
	} else if len(token) < 24 {
		return errors.New("ключ панели слишком короткий")
	}
	ln, err := net.Listen("tcp4", listen)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s := &server{
		cfgPath: cfgPath, token: token, out: out,
		host: ln.Addr().String(), quit: cancel, lastPing: time.Now(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handlePage)
	mux.HandleFunc("GET /api/state", s.handleState)
	mux.HandleFunc("GET /api/processes", s.handleProcesses)
	mux.HandleFunc("GET /api/watch", s.handleWatch)
	mux.HandleFunc("POST /api/watch", s.handleWatchStart)
	mux.HandleFunc("POST /api/watch/stop", s.handleWatchStop)
	mux.HandleFunc("POST /api/add", s.handleAdd)
	mux.HandleFunc("POST /api/config", s.handleConfigSave)
	mux.HandleFunc("POST /api/ping", s.handlePing)
	mux.HandleFunc("POST /api/quit", s.handleQuit)
	srv := &http.Server{Handler: s.guard(mux), ReadHeaderTimeout: 5 * time.Second}

	url := "http://" + s.host + "/?t=" + s.token
	fmt.Fprintf(out, "Панель управления открыта: %s\n", url)
	fmt.Fprintln(out, "Она работает, пока открыто это окно. Закрыть: кнопка «Закрыть панель» на странице или Ctrl+C здесь.")
	if o.OpenBrowser {
		openURL(url)
	}

	go func() { // сторож: закрываем панель, когда ею перестали пользоваться
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.mu.Lock()
				limit := idleBeforeOpen
				if s.opened {
					limit = idleAfterOpen
				}
				idle := time.Since(s.lastPing) > limit
				s.mu.Unlock()
				if idle {
					fmt.Fprintln(out, "Страница закрыта — панель завершает работу.")
					cancel()
					return
				}
			}
		}
	}()
	go func() {
		<-ctx.Done()
		s.mu.Lock()
		if s.watch != nil {
			s.watch.stop()
		}
		s.mu.Unlock()
		shut, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		_ = srv.Shutdown(shut)
	}()

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// guard пропускает только запросы с этого компьютера и с ключом панели.
func (s *server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Имя узла должно быть ровно нашим адресом: так чужой сайт не сможет
		// обратиться к панели, подставив своё доменное имя на 127.0.0.1.
		if r.Host != s.host {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		given := r.Header.Get("X-Ipblock-Token")
		if r.URL.Path == "/" {
			given = r.URL.Query().Get("t")
		}
		if subtle.ConstantTimeCompare([]byte(given), []byte(s.token)) != 1 {
			http.Error(w, "Панель открывается только по ссылке, которую печатает команда ipblock ui.", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *server) handlePage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'")
	_, _ = io.WriteString(w, strings.Replace(page, "{{TOKEN}}", s.token, 1))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, format string, args ...any) {
	writeJSON(w, status, map[string]string{"error": fmt.Sprintf(format, args...)})
}

type ruleView struct {
	Name      string   `json:"name"`
	Source    string   `json:"source"`
	AllowFrom []string `json:"allow_from"`
	Domains   []string `json:"domains"`
	IPs       []string `json:"ips"`
	Apps      []string `json:"apps"`
	Known     bool     `json:"known"` // сервис уже вынес решение по этому правилу
	Allowed   bool     `json:"allowed"`
	Note      string   `json:"note,omitempty"`
}

type seenView struct {
	IP       string   `json:"ip"`
	Services []string `json:"services"`
}

type stateView struct {
	Service   string   `json:"service"` // ok | stale | none
	CheckedAt string   `json:"checked_at,omitempty"`
	PublicIPs []string `json:"public_ips"`
	// Что ответил каждый сервис определения IP: «адрес → какие сервисы его видят».
	SeenAs     []seenView `json:"seen_as"`
	PublicErr  string     `json:"public_error,omitempty"`
	Warnings   []string   `json:"warnings"`
	Rules      []ruleView `json:"rules"`
	ConfigPath string     `json:"config_path"`
	ConfigErr  string     `json:"config_error,omitempty"`
	// Настройки для редактирования и их версия; nil — файл не читается как YAML.
	Config   *config.Editable `json:"config"`
	Version  string           `json:"version"`
	Missing  bool             `json:"missing"` // файла настроек ещё нет
	CanWrite bool             `json:"can_write"`
	OS       string           `json:"os"`
}

func (s *server) handleState(w http.ResponseWriter, _ *http.Request) {
	v := stateView{
		Service: "none", ConfigPath: s.cfgPath, OS: runtime.GOOS,
		PublicIPs: []string{}, SeenAs: []seenView{}, Warnings: []string{}, Rules: []ruleView{},
	}
	if f, err := os.OpenFile(s.cfgPath, os.O_WRONLY|os.O_APPEND, 0); err == nil {
		f.Close()
		v.CanWrite = true
	} else if os.IsNotExist(err) {
		// Файла ещё нет: права выяснятся при первом сохранении.
		v.CanWrite, v.Missing = true, true
	}

	var snap engine.Snapshot
	if data, err := os.ReadFile(engine.StatusPath(s.cfgPath)); err == nil && json.Unmarshal(data, &snap) == nil {
		v.Service = "ok"
		if time.Since(snap.Time) > 2*time.Duration(snap.IntervalSec)*time.Second+30*time.Second {
			v.Service = "stale"
		}
		v.CheckedAt = snap.Time.Format("02.01.2006 15:04:05")
		for _, a := range snap.Answers {
			if !a.OK() || a.Stale {
				continue
			}
			ip := a.Addr.String()
			if i := slices.Index(v.PublicIPs, ip); i >= 0 {
				v.SeenAs[i].Services = append(v.SeenAs[i].Services, a.Host())
			} else {
				v.PublicIPs = append(v.PublicIPs, ip)
				v.SeenAs = append(v.SeenAs, seenView{IP: ip, Services: []string{a.Host()}})
			}
		}
		v.PublicErr = snap.PublicErr
		v.Warnings = append(v.Warnings, snap.Warnings...)
	}

	// Правила показываем так, как они записаны в файле, даже если в них ошибка:
	// иначе её нельзя было бы исправить в панели.
	ed, ver, err := config.LoadEditable(s.cfgPath)
	if err != nil {
		v.ConfigErr = err.Error()
		writeJSON(w, http.StatusOK, v)
		return
	}
	v.Config, v.Version = &ed, ver
	if !v.Missing {
		if _, err := config.Load(s.cfgPath); err != nil {
			v.ConfigErr = err.Error()
		}
	}
	for i, r := range ed.Rules {
		rv := ruleView{
			Name: r.Name, Source: r.IPSource,
			AllowFrom: r.AllowFrom, Domains: r.Domains, IPs: r.IPs, Apps: []string{},
		}
		if rv.Name == "" {
			rv.Name = fmt.Sprintf("rule-%d", i+1) // так сервис называет безымянные правила
		}
		if rv.Source == "" {
			rv.Source = config.SourcePublic
		}
		for _, a := range r.Apps {
			p := a.Darwin
			if runtime.GOOS == "windows" || p == "" {
				if a.Windows != "" {
					p = a.Windows
				}
			}
			if p != "" {
				rv.Apps = append(rv.Apps, p)
			}
		}
		if v.Service == "ok" {
			for _, st := range snap.Rules {
				if st.Name == rv.Name {
					rv.Known, rv.Allowed, rv.Note = true, st.Allowed, st.Note
				}
			}
		}
		v.Rules = append(v.Rules, rv)
	}
	writeJSON(w, http.StatusOK, v)
}

type procGroup struct {
	Key   string `json:"key"`
	Name  string `json:"name"`
	Path  string `json:"path"`
	Procs int    `json:"procs"`
	Conns int    `json:"conns"`
}

func (s *server) handleProcesses(w http.ResponseWriter, _ *http.Request) {
	list, err := procs.List()
	if err != nil {
		fail(w, http.StatusInternalServerError, "не удалось получить список процессов: %v", err)
		return
	}
	cs, _ := conns.Snapshot()
	byPID := map[int]int{}
	for _, c := range cs {
		byPID[c.PID]++
	}
	groups := map[string]*procGroup{}
	self := os.Getpid()
	for _, p := range list {
		if p.PID == self {
			continue
		}
		k := groupKey(p)
		g := groups[k]
		if g == nil {
			g = &procGroup{Key: k, Name: groupName(p), Path: groupPath(p)}
			groups[k] = g
		}
		g.Procs++
		g.Conns += byPID[p.PID]
	}
	out := make([]*procGroup, 0, len(groups))
	for _, g := range groups {
		out = append(out, g)
	}
	// Сверху те, кто сейчас ходит в сеть.
	slices.SortFunc(out, func(a, b *procGroup) int {
		if a.Conns != b.Conns {
			return b.Conns - a.Conns
		}
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	writeJSON(w, http.StatusOK, out)
}

func (s *server) handleWatchStart(w http.ResponseWriter, r *http.Request) {
	var req struct{ Key, Name, Path string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil || req.Key == "" {
		fail(w, http.StatusBadRequest, "не указана программа")
		return
	}
	s.mu.Lock()
	if s.watch != nil {
		s.watch.stop()
	}
	s.watch = startWatch(req.Key, req.Name, req.Path)
	wv := s.watch.view()
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, wv)
}

func (s *server) handleWatchStop(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.watch == nil {
		writeJSON(w, http.StatusOK, watchView{Items: []foundView{}})
		return
	}
	s.watch.stop()
	writeJSON(w, http.StatusOK, s.watch.view())
}

func (s *server) handleWatch(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.watch == nil {
		writeJSON(w, http.StatusOK, watchView{Items: []foundView{}})
		return
	}
	writeJSON(w, http.StatusOK, s.watch.view())
}

func (s *server) handleAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Rule      string   `json:"rule"`
		NewName   string   `json:"new_name"`
		AllowFrom []string `json:"allow_from"`
		IPs       []string `json:"ips"`
		Subnets   bool     `json:"subnets"`
		App       bool     `json:"app"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "неверный запрос")
		return
	}
	add := config.Addition{Rule: req.Rule, NewName: req.NewName, AllowFrom: req.AllowFrom}
	for _, raw := range req.IPs {
		ip, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			fail(w, http.StatusBadRequest, "неверный адрес %q", raw)
			return
		}
		add.IPs = append(add.IPs, widen(ip.Unmap(), req.Subnets))
	}
	slices.Sort(add.IPs)
	add.IPs = slices.Compact(add.IPs)

	if req.App {
		s.mu.Lock()
		if s.watch != nil && filepath.IsAbs(s.watch.path) {
			add.AppPath = s.watch.path
		}
		s.mu.Unlock()
		if add.AppPath == "" {
			fail(w, http.StatusBadRequest, "путь к программе неизвестен — добавить её в правило нельзя, снимите эту галочку")
			return
		}
	}
	if len(add.IPs) == 0 && add.AppPath == "" {
		fail(w, http.StatusBadRequest, "не выбрано ни одного адреса")
		return
	}
	if err := config.Add(s.cfgPath, add); err != nil {
		if os.IsPermission(err) {
			fail(w, http.StatusForbidden, "нет прав на запись настроек — запустите панель от имени администратора")
			return
		}
		fail(w, http.StatusBadRequest, "%v", err)
		return
	}
	name := req.Rule
	if name == "" {
		name = req.NewName
	}
	writeJSON(w, http.StatusOK, map[string]any{"rule": name, "ips": len(add.IPs), "app": add.AppPath != ""})
}

// widen превращает адрес в запись для настроек: сам адрес либо его подсеть
// (/24 для IPv4, /64 для IPv6) — серверы одного сервиса обычно стоят рядом.
func widen(ip netip.Addr, subnet bool) string {
	if !subnet {
		return ip.String()
	}
	bits := 24
	if ip.Is6() {
		bits = 64
	}
	p, _ := ip.Prefix(bits)
	return p.String()
}

func (s *server) handlePing(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	first := !s.opened
	s.lastPing, s.opened = time.Now(), true
	s.mu.Unlock()
	if first {
		fmt.Fprintln(s.out, "Страница панели открыта в браузере.")
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) handleQuit(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	go s.quit()
}

// handleConfigSave записывает настройки целиком: так панель правит правила и общие параметры.
func (s *server) handleConfigSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Version string          `json:"version"`
		Config  config.Editable `json:"config"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "неверный запрос")
		return
	}
	err := config.Save(s.cfgPath, req.Version, req.Config)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case errors.Is(err, config.ErrChanged):
		fail(w, http.StatusConflict, "%v", err)
	case os.IsPermission(err):
		fail(w, http.StatusForbidden, "нет прав на запись настроек — запустите панель от имени администратора")
	default:
		fail(w, http.StatusBadRequest, "%v", err)
	}
}
