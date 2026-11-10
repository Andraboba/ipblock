// Package config описывает и загружает файл настроек ipblock.
package config

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"ipblock/internal/netmatch"
)

// Источник «текущего» IP компьютера.
const (
	SourcePublic = "public" // внешний IP, каким его видит интернет (офисный NAT)
	SourceLocal  = "local"  // адреса сетевых интерфейсов (например 10.20.x.x в офисной сети)
	SourceAny    = "any"    // достаточно совпадения любого из них
)

// Что делать с блокировками при остановке сервиса.
const (
	StopLock  = "lock"  // закрыть доступ полностью, пока сервис не запустится снова
	StopClear = "clear" // снять все блокировки (доступ открыт всем)
)

// Example — пример конфига, который записывает команда `ipblock init`.
//
//go:embed example.yaml
var Example []byte

// Действия с приложениями.
const (
	ActionNetwork = "network" // заблокировать приложению сеть (только Windows)
	ActionKill    = "kill"    // завершать процесс, пока доступ запрещён
)

type Config struct {
	// Как часто перепроверять IP. По умолчанию 20s.
	CheckInterval Duration `yaml:"check_interval"`
	// Сервисы, возвращающие внешний IP простым текстом.
	PublicIPServices []string `yaml:"public_ip_services"`
	// Файл журнала. Пусто — рядом с конфигом (ipblock.log).
	LogFile string `yaml:"log_file"`
	// lock (по умолчанию) или clear — что делать с блокировками при остановке сервиса.
	OnStop string `yaml:"on_stop"`
	Rules  []Rule `yaml:"rules"`
}

type Rule struct {
	Name string `yaml:"name"`
	// public | local | any. По умолчанию public.
	IPSource string `yaml:"ip_source"`
	// Откуда доступ РАЗРЕШЁН: IP, CIDR, диапазон или шаблон 10.1.*.*
	AllowFrom []string `yaml:"allow_from"`
	// Сайты: закрываются через hosts и (по запомненным IP) файрволом. Поддомены перечисляются явно.
	Domains []string `yaml:"domains"`
	// Запоминать IP-адреса доменов (пока доступ открыт) и закрывать их в файрволе.
	// По умолчанию включено; выключить — resolve_domains: false.
	ResolveDomains *bool `yaml:"resolve_domains"`
	// IP/подсети назначения, которые блокируются файрволом.
	IPs []string `yaml:"ips"`
	// Приложения.
	Apps []App `yaml:"apps"`
	// Сервисы определения внешнего IP для этого правила. Пусто — общий список.
	// Нужны, когда VPN ведёт трафик к разным сайтам через разные серверы: тогда здесь
	// указывают сервис, идущий тем же путём, что и защищаемый сайт.
	IPServices []string `yaml:"ip_services"`

	AllowMatchers []netmatch.Matcher `yaml:"-"`
}

type App struct {
	// Путь к .exe на Windows или к папке — тогда закрываются все .exe в ней.
	Windows string `yaml:"windows"`
	// Путь к .app (или исполняемому файлу) на macOS.
	Darwin string `yaml:"darwin"`
	// network | kill. По умолчанию: Windows — network, macOS — kill.
	Action string `yaml:"action"`
}

// Path возвращает путь приложения для текущей ОС.
func (a App) Path() string {
	switch runtime.GOOS {
	case "windows":
		return a.Windows
	case "darwin":
		return a.Darwin
	}
	return ""
}

// EffectiveAction возвращает действие с учётом умолчаний и возможностей ОС.
func (a App) EffectiveAction() string {
	act := strings.ToLower(strings.TrimSpace(a.Action))
	if act == "" {
		if runtime.GOOS == "windows" {
			return ActionNetwork
		}
		return ActionKill
	}
	if act == ActionNetwork && runtime.GOOS != "windows" {
		// В macOS нет встроенного исходящего файрвола по приложениям.
		return ActionKill
	}
	return act
}

// Duration позволяет писать в YAML "30s", "2m".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("неверная длительность %q: %w", n.Value, err)
	}
	d.Duration = v
	return nil
}

// DefaultPath — где сервис ищет конфиг по умолчанию.
func DefaultPath() string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "ipblock", "config.yaml")
	case "darwin":
		return "/Library/Application Support/ipblock/config.yaml"
	}
	return "/etc/ipblock/config.yaml"
}

// Load читает и проверяет конфиг.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.normalize(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.LogFile == "" {
		c.LogFile = filepath.Join(filepath.Dir(path), "ipblock.log")
	}
	return &c, nil
}

func (c *Config) normalize() error {
	if c.CheckInterval.Duration == 0 {
		c.CheckInterval.Duration = 20 * time.Second
	}
	if c.CheckInterval.Duration < 5*time.Second {
		return fmt.Errorf("check_interval должен быть не меньше 5s")
	}
	if len(c.PublicIPServices) == 0 {
		c.PublicIPServices = []string{
			"https://api.ipify.org",
			"https://ifconfig.me/ip",
			"https://icanhazip.com",
			"https://checkip.amazonaws.com",
		}
	}
	c.OnStop = strings.ToLower(strings.TrimSpace(c.OnStop))
	switch c.OnStop {
	case "", "keep": // keep — прежнее название lock
		c.OnStop = StopLock
	case StopLock, StopClear:
	default:
		return fmt.Errorf("on_stop должен быть lock или clear")
	}
	if len(c.Rules) == 0 {
		return fmt.Errorf("не задано ни одного правила (rules)")
	}

	seen := map[string]bool{}
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.Name == "" {
			r.Name = fmt.Sprintf("rule-%d", i+1)
		}
		if seen[r.Name] {
			return fmt.Errorf("повторяющееся имя правила %q", r.Name)
		}
		seen[r.Name] = true

		r.IPSource = strings.ToLower(strings.TrimSpace(r.IPSource))
		if r.IPSource == "" {
			r.IPSource = SourcePublic
		}
		switch r.IPSource {
		case SourcePublic, SourceLocal, SourceAny:
		default:
			return fmt.Errorf("правило %q: ip_source должен быть public, local или any", r.Name)
		}

		if len(r.AllowFrom) == 0 {
			return fmt.Errorf("правило %q: пустой allow_from — доступ был бы запрещён всегда", r.Name)
		}
		ms, err := netmatch.ParseList(r.AllowFrom)
		if err != nil {
			return fmt.Errorf("правило %q: allow_from: %w", r.Name, err)
		}
		r.AllowMatchers = ms

		for j, d := range r.Domains {
			d = strings.ToLower(strings.TrimSpace(d))
			d = strings.TrimPrefix(strings.TrimPrefix(d, "https://"), "http://")
			d, _, _ = strings.Cut(d, "/")
			if d == "" || strings.ContainsAny(d, " *") {
				return fmt.Errorf("правило %q: неверный домен %q (шаблоны * в hosts не работают — перечислите поддомены)", r.Name, r.Domains[j])
			}
			r.Domains[j] = d
		}
		for _, ip := range r.IPs {
			if _, err := netmatch.Prefixes(ip); err != nil {
				return fmt.Errorf("правило %q: ips: %w", r.Name, err)
			}
		}
		for j, s := range r.IPServices {
			s = strings.TrimSpace(s)
			if !strings.HasPrefix(s, "https://") && !strings.HasPrefix(s, "http://") {
				return fmt.Errorf("правило %q: ip_services: %q — нужен адрес вида https://…", r.Name, s)
			}
			r.IPServices[j] = s
		}
		for _, a := range r.Apps {
			switch a.EffectiveAction() {
			case ActionNetwork, ActionKill:
			default:
				return fmt.Errorf("правило %q: action должен быть network или kill", r.Name)
			}
		}
		if len(r.Domains) == 0 && len(r.IPs) == 0 && len(r.Apps) == 0 {
			return fmt.Errorf("правило %q: нечего блокировать (domains, ips, apps пусты)", r.Name)
		}
	}
	return nil
}

// NeedsPublic / NeedsLocal — какие источники IP требуются хотя бы одному правилу.
func (c *Config) NeedsPublic() bool {
	for _, r := range c.Rules {
		if r.IPSource == SourcePublic || r.IPSource == SourceAny {
			return true
		}
	}
	return false
}

func (c *Config) NeedsLocal() bool {
	for _, r := range c.Rules {
		if r.IPSource == SourceLocal || r.IPSource == SourceAny {
			return true
		}
	}
	return false
}

// NeedsPublicV6 — есть ли правила, где в allow_from указан IPv6:
// только тогда имеет смысл отдельно узнавать внешний IPv6.
func (c *Config) NeedsPublicV6() bool {
	for _, r := range c.Rules {
		if r.IPSource == SourceLocal {
			continue
		}
		for _, a := range r.AllowFrom {
			if strings.Contains(a, ":") {
				return true
			}
		}
	}
	return false
}

// Resolve сообщает, нужно ли запоминать и закрывать IP-адреса доменов правила.
func (r Rule) Resolve() bool { return r.ResolveDomains == nil || *r.ResolveDomains }

// ServicesFor возвращает сервисы определения внешнего IP, по которым судят о правиле.
func (c *Config) ServicesFor(r Rule) []string {
	if r.IPSource == SourceLocal {
		return nil
	}
	if len(r.IPServices) > 0 {
		return r.IPServices
	}
	return c.PublicIPServices
}

// AllServices — все сервисы, которые нужно опросить за одну проверку, без повторов.
func (c *Config) AllServices() []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range c.Rules {
		for _, s := range c.ServicesFor(r) {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}
