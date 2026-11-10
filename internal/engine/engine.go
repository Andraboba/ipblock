// Package engine проверяет IP и приводит блокировки в соответствие с правилами.
//
// Принцип — «закрыто, пока не доказано обратное»:
//
//   - при запуске, при любой смене сети, после сна и при остановке доступ сначала
//     закрывается полностью и только потом перепроверяется;
//   - открытый доступ привязан в файрволе к тому локальному адресу, с которого шла
//     проверка: соединение через другой интерфейс ядро не пропустит;
//   - если IP определить не удалось, доступ закрыт.
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"ipblock/internal/config"
	"ipblock/internal/detect"
	"ipblock/internal/firewall"
	"ipblock/internal/hosts"
	"ipblock/internal/netmatch"
	"ipblock/internal/netwatch"
	"ipblock/internal/procs"
)

const (
	// Как часто пересоздаём правила файрвола, даже если ничего не менялось
	// (на случай, если их удалила другая программа).
	firewallResync = 3 * time.Minute
	// Как часто проверяем, не запущено ли запрещённое приложение.
	killInterval = time.Second
	// Пауза после смены сети перед перепроверкой: сеть должна успеть подняться.
	settleDelay = 1500 * time.Millisecond
	// После смены сети несколько проверок идут чаще обычного: VPN поднимает маршруты
	// не мгновенно, и первая проверка может ещё увидеть прежний внешний адрес.
	fastChecks   = 4
	fastInterval = 4 * time.Second
)

// RuleStatus — решение по одному правилу.
type RuleStatus struct {
	Name    string `json:"name"`
	Source  string `json:"ip_source"`
	Allowed bool   `json:"allowed"`
	// Локальные адреса, с которых доступ подтверждён и открыт.
	AllowedLocal []netip.Addr `json:"allowed_local,omitempty"`
	Note         string       `json:"note,omitempty"`
}

func joinAddrs(a []netip.Addr) string {
	s := make([]string, len(a))
	for i, ip := range a {
		s[i] = ip.String()
	}
	return strings.Join(s, ", ")
}

// StatusPath — файл, в который сервис пишет результат последней проверки.
func StatusPath(cfgPath string) string {
	return filepath.Join(filepath.Dir(cfgPath), "status.json")
}

// ClearAll снимает все блокировки, поставленные ipblock.
func ClearAll() error {
	changed, hErr := hosts.Apply(nil)
	if changed {
		hosts.FlushDNS()
	}
	fErr := firewall.Clear()
	if hErr != nil {
		return fmt.Errorf("hosts: %w", hErr)
	}
	return fErr
}

type Engine struct {
	cfgPath string
	cfg     *config.Config
	cfgMod  time.Time
	log     *log.Logger

	events   chan struct{}
	prev     map[string]bool // прошлое решение по каждому правилу
	fwKey    string          // состояние файрвола, применённое последним
	fwTime   time.Time
	fwErr    string // почему файрвол сейчас не в нужном состоянии
	hostsErr string
	learned  *learned
	warned   map[string]bool
	lastTick time.Time
	fast     int                   // сколько ближайших проверок сделать с коротким интервалом
	memory   map[string]remembered // последний ответ каждого сервиса определения IP
	pubDown  bool                  // внешний IP сейчас не определяется (чтобы не писать об этом в журнал каждый раз)

	mu   sync.Mutex
	kill []string
}

func New(cfgPath string, cfg *config.Config, logger *log.Logger) *Engine {
	e := &Engine{
		cfgPath: cfgPath,
		cfg:     cfg,
		log:     logger,
		events:  make(chan struct{}, 1),
		prev:    map[string]bool{},
		learned: loadLearned(filepath.Join(filepath.Dir(cfgPath), "learned.json")),
		warned:  map[string]bool{},
	}
	if fi, err := os.Stat(cfgPath); err == nil {
		e.cfgMod = fi.ModTime()
	}
	return e
}

// Run работает до отмены ctx.
func (e *Engine) Run(ctx context.Context) error {
	e.log.Printf("ipblock запущен: конфиг %s, правил %d, проверка каждые %s",
		e.cfgPath, len(e.cfg.Rules), e.cfg.CheckInterval.Duration)

	// Первым делом — полный запрет, ещё до любых обращений в сеть.
	e.lock(ctx, "запуск: доступ закрыт до первой проверки", true)

	if err := netwatch.Watch(ctx, e.events); err != nil {
		e.log.Printf("не удалось подписаться на изменения сети (%v): смена сети будет замечена только при очередной проверке", err)
	}
	go e.killLoop(ctx)

	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			e.stop()
			return nil

		case <-e.events:
			e.lock(ctx, "сеть изменилась: доступ закрыт до перепроверки", false)
			select {
			case <-ctx.Done():
				e.stop()
				return nil
			case <-time.After(settleDelay):
			}
			e.fast = fastChecks
			// Сигналы, пришедшие за время паузы, уже учтены: доступ закрыт.
			select {
			case <-e.events:
			default:
			}
			e.tick(ctx)

		case <-timer.C:
			// Часы ушли далеко вперёд — компьютер спал и мог проснуться в другой сети.
			if !e.lastTick.IsZero() && time.Since(e.lastTick.Round(0)) > 2*e.cfg.CheckInterval.Duration+10*time.Second {
				e.lock(ctx, "компьютер выходил из сна: доступ закрыт до перепроверки", false)
			}
			e.reload()
			e.tick(ctx)
		}
		next := e.cfg.CheckInterval.Duration
		if e.fast > 0 {
			e.fast--
			next = min(next, fastInterval)
		}
		timer.Reset(next)
	}
}

func (e *Engine) stop() {
	if e.cfg.OnStop == config.StopClear {
		if err := ClearAll(); err != nil {
			e.log.Printf("не удалось снять блокировки: %v", err)
		} else {
			e.log.Print("остановка: блокировки сняты (on_stop: clear)")
		}
		return
	}
	e.lock(context.Background(), "сервис остановлен: доступ закрыт", false)
	e.log.Print("остановка: доступ закрыт полностью (on_stop: lock)")
}

// reload перечитывает конфиг, если файл изменился. Ошибочный конфиг не применяется.
func (e *Engine) reload() {
	fi, err := os.Stat(e.cfgPath)
	if err != nil || fi.ModTime().Equal(e.cfgMod) {
		return
	}
	e.cfgMod = fi.ModTime()
	cfg, err := config.Load(e.cfgPath)
	if err != nil {
		e.log.Printf("конфиг изменился, но в нём ошибка — работаю по старому: %v", err)
		return
	}
	e.cfg = cfg
	e.warned = map[string]bool{}
	e.log.Printf("конфиг перечитан: правил %d", len(cfg.Rules))
}

// lock закрывает доступ по всем правилам, ничего не проверяя.
func (e *Engine) lock(ctx context.Context, note string, startup bool) {
	snap := locked(e.cfg, note)
	wasOpen := false
	for _, open := range e.prev {
		wasOpen = wasOpen || open
	}
	if wasOpen || startup {
		e.log.Print(note)
	}
	e.prev = map[string]bool{}
	for _, r := range snap.Rules {
		e.prev[r.Name] = false
	}
	e.memory = nil // сеть могла смениться: прежние ответы сервисов больше ничего не значат
	e.apply(ctx, &snap, startup)
	e.writeStatus(snap)
}

func (e *Engine) tick(ctx context.Context) {
	e.lastTick = time.Now()
	answers := e.withMemory(Probe(ctx, e.cfg))
	snap := Decide(e.cfg, answers, localIPs(e.cfg))
	if ctx.Err() != nil {
		return // остановка посреди проверки: не делаем выводов из оборванных запросов
	}
	if len(e.events) > 0 {
		// Сеть сменилась, пока шла проверка: её результат относится к прежней сети.
		// Главный цикл сейчас закроет доступ и проверит заново.
		return
	}
	if snap.PublicErr != "" && !e.pubDown {
		e.log.Printf("%s — правила по внешнему IP закрыты", snap.PublicErr)
	}
	e.pubDown = snap.PublicErr != ""

	for _, r := range snap.Rules {
		if old, known := e.prev[r.Name]; !known || old != r.Allowed {
			if r.Allowed {
				e.log.Printf("правило %q: доступ ОТКРЫТ (внешний IP: %s; только с локального адреса %s)",
					r.Name, snap.PublicAddrs(), joinAddrs(r.AllowedLocal))
			} else {
				why := ""
				if r.Note != "" {
					why = " — " + r.Note
				}
				e.log.Printf("правило %q: доступ ЗАКРЫТ (внешний IP: %s; локальные: %s)%s",
					r.Name, snap.PublicAddrs(), joinAddrs(snap.LocalIPs), why)
			}
		}
	}
	e.prev = map[string]bool{}
	for _, r := range snap.Rules {
		e.prev[r.Name] = r.Allowed
	}

	e.apply(ctx, &snap, false)
	e.writeStatus(snap)
}

func (e *Engine) writeStatus(snap Snapshot) {
	if data, err := json.MarshalIndent(snap, "", "  "); err == nil {
		_ = os.WriteFile(StatusPath(e.cfgPath), data, 0o644)
	}
}

// apply приводит файрвол, hosts и список закрываемых программ к решению snap.
// Порядок важен: сначала файрвол (ядро), потом всё остальное.
func (e *Engine) apply(ctx context.Context, snap *Snapshot, startup bool) {
	fw, domains, kill := e.build(snap)
	e.applyFirewall(fw, startup)

	changed, err := hosts.Apply(domains)
	if err != nil {
		e.hostsErr = fmt.Sprintf("не удалось обновить hosts: %v", err)
		e.warnOnce("%s", e.hostsErr)
	} else {
		e.hostsErr = ""
		if changed {
			hosts.FlushDNS()
			e.log.Printf("hosts обновлён: закрыто доменов — %d", len(domains))
		}
	}

	e.mu.Lock()
	e.kill = kill
	e.mu.Unlock()
	e.killNow()

	// Адреса сайтов узнаём только пока доступ открыт: с чужого адреса к их DNS не
	// обращаемся вовсе. Новые адреса сразу попадают в файрвол: с этой секунды они
	// привязаны к проверенному локальному адресу, как и остальные.
	if e.learn(ctx, snap) {
		fw, _, _ = e.build(snap)
		e.applyFirewall(fw, false)
	}

	snap.Warnings = append(snap.Warnings, firewall.Health()...)
	for _, w := range []string{e.fwErr, e.hostsErr} {
		if w != "" {
			snap.Warnings = append(snap.Warnings, w)
		}
	}
}

// build переводит решение snap в состояние файрвола, список доменов для hosts
// и список программ, которые нужно закрывать.
func (e *Engine) build(snap *Snapshot) (fw firewall.State, domains, kill []string) {

	for i, r := range e.cfg.Rules {
		st := snap.Rules[i]
		blk := firewall.Block{Allow: st.AllowedLocal}

		for _, ip := range r.IPs {
			ps, _ := netmatch.Prefixes(ip) // проверено при загрузке конфига
			blk.Dst = append(blk.Dst, ps...)
		}
		if r.Resolve() {
			for _, d := range r.Domains {
				blk.Dst = append(blk.Dst, e.learned.prefixes(d)...)
			}
		}
		for _, a := range r.Apps {
			p := a.Path()
			if p == "" {
				continue
			}
			if runtime.GOOS == "windows" {
				if filepath.IsAbs(p) {
					blk.Apps = append(blk.Apps, firewall.ExpandApp(p)...)
				} else if a.EffectiveAction() == config.ActionNetwork {
					e.warnOnce("правило %q: чтобы закрыть программе сеть, нужен полный путь; %q пропущено", r.Name, p)
				}
			}
			if !st.Allowed && a.EffectiveAction() == config.ActionKill {
				kill = append(kill, p)
			}
		}
		if !st.Allowed {
			domains = append(domains, r.Domains...)
		}
		fw = append(fw, blk)
	}
	return fw, domains, kill
}

func (e *Engine) applyFirewall(fw firewall.State, startup bool) {
	fw.Normalize()
	key := fw.Key()
	if !startup && key == e.fwKey && time.Since(e.fwTime) < firewallResync {
		return
	}

	var err error
	if startup {
		err = firewall.Lockdown(fw)
	} else {
		err = firewall.Apply(fw)
	}
	if err == nil {
		if key != e.fwKey {
			dst, apps := fw.Count()
			e.log.Printf("файрвол обновлён: адресов — %d, программ — %d", dst, apps)
		}
		e.fwKey, e.fwTime, e.fwErr = key, time.Now(), ""
		return
	}

	// Нужное состояние не применилось. Закрываем всё полностью: лучше лишний запрет, чем утечка.
	e.log.Printf("файрвол: %v — закрываю доступ полностью", err)
	lockedState := fw.Locked()
	if err2 := firewall.Apply(lockedState); err2 != nil {
		e.fwKey = ""
		e.fwErr = fmt.Sprintf("ФАЙРВОЛ НЕ РАБОТАЕТ, адреса и программы не защищены: %v", err2)
		e.log.Print(e.fwErr)
		return
	}
	// Ключ запоминаем от «закрытого» состояния: на следующей проверке попробуем снова.
	e.fwKey, e.fwTime = lockedState.Key(), time.Now()
	e.fwErr = fmt.Sprintf("файрвол не принял правила с привязкой к адресу, доступ закрыт полностью: %v", err)
}

// learn запоминает текущие адреса доменов тех правил, по которым доступ открыт.
// Возвращает true, если появились адреса, которых раньше не было.
func (e *Engine) learn(ctx context.Context, snap *Snapshot) bool {
	added := false
	any := false
	for i, r := range e.cfg.Rules {
		if !snap.Rules[i].Allowed || !r.Resolve() {
			continue
		}
		for _, d := range r.Domains {
			lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			addrs, err := net.DefaultResolver.LookupNetIP(lctx, "ip", d)
			cancel()
			if err != nil {
				continue
			}
			any = true
			if e.learned.add(d, addrs) {
				added = true
			}
		}
	}
	if any {
		e.learned.save(added)
	}
	return added
}

func (e *Engine) killLoop(ctx context.Context) {
	t := time.NewTicker(killInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.killNow()
		}
	}
}

func (e *Engine) killNow() {
	e.mu.Lock()
	targets := e.kill
	e.mu.Unlock()
	for _, name := range procs.Kill(targets) {
		e.log.Printf("закрыто приложение %s: доступ с текущего адреса запрещён", name)
	}
}

// warnOnce пишет одно и то же предупреждение в журнал только один раз (до перечитывания конфига).
func (e *Engine) warnOnce(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if e.warned[msg] {
		return
	}
	e.warned[msg] = true
	e.log.Print(msg)
}

// Сколько времени помним ответ сервиса, который перестал отвечать.
const answerMemory = 5 * time.Minute

type remembered struct {
	addr, local netip.Addr
	at          time.Time
}

// withMemory подставляет недавний ответ тем сервисам, которые сейчас не ответили.
//
// Без этого решение «прыгало» бы: сервис, видящий неразрешённый адрес, не ответил —
// доступ открылся; ответил — закрылся. Подставленный ответ помечен как устаревший
// и может только удержать доступ закрытым, но не открыть его.
func (e *Engine) withMemory(answers []detect.Answer) []detect.Answer {
	if e.memory == nil {
		e.memory = map[string]remembered{}
	}
	now := time.Now()
	for i, a := range answers {
		key := a.Service
		if a.V6 {
			key += "|6"
		}
		if a.OK() {
			e.memory[key] = remembered{a.Addr, a.Local, now}
			continue
		}
		if m, ok := e.memory[key]; ok && now.Sub(m.at) < answerMemory {
			answers[i].Addr, answers[i].Local, answers[i].Stale = m.addr, m.local, true
		}
	}
	return answers
}
