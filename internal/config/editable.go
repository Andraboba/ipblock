package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Editable — настройки в том виде, в каком они записаны в файле (без подстановки
// умолчаний). Это то, что показывает и сохраняет панель управления.
type Editable struct {
	CheckInterval    string     `json:"check_interval" yaml:"check_interval"`
	OnStop           string     `json:"on_stop" yaml:"on_stop"`
	LogFile          string     `json:"log_file" yaml:"log_file"`
	PublicIPServices []string   `json:"public_ip_services" yaml:"public_ip_services"`
	Rules            []EditRule `json:"rules" yaml:"rules"`
}

type EditRule struct {
	// Index — номер правила в файле на момент чтения; -1 — новое правило.
	// По нему сохранение находит прежнюю запись и оставляет её комментарии.
	Index          int       `json:"index" yaml:"-"`
	Name           string    `json:"name" yaml:"name"`
	IPSource       string    `json:"ip_source" yaml:"ip_source"`
	AllowFrom      []string  `json:"allow_from" yaml:"allow_from"`
	Domains        []string  `json:"domains" yaml:"domains"`
	ResolveDomains *bool     `json:"-" yaml:"resolve_domains"`
	Resolve        bool      `json:"resolve_domains" yaml:"-"`
	IPs            []string  `json:"ips" yaml:"ips"`
	Apps           []EditApp `json:"apps" yaml:"apps"`
	IPServices     []string  `json:"ip_services" yaml:"ip_services"`
}

type EditApp struct {
	Windows string `json:"windows" yaml:"windows"`
	Darwin  string `json:"darwin" yaml:"darwin"`
	Action  string `json:"action" yaml:"action"`
}

// ErrChanged — файл настроек изменился с момента, когда его прочитала панель.
var ErrChanged = errors.New("файл настроек изменился, пока вы его редактировали — обновите страницу и повторите")

const versionNew = "new" // файла ещё нет

func versionOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}

// LoadEditable читает настройки для редактирования. version нужно передать в Save:
// так обнаруживается, что файл тем временем изменили другим способом.
// Отсутствующий файл — не ошибка: возвращаются пустые настройки.
func LoadEditable(path string) (e Editable, version string, err error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return emptyLists(Editable{}), versionNew, nil
	}
	if err != nil {
		return e, "", err
	}
	if err := yaml.Unmarshal(data, &e); err != nil {
		return e, "", fmt.Errorf("файл настроек не читается: %w", err)
	}
	for i := range e.Rules {
		r := &e.Rules[i]
		r.Index = i
		r.Resolve = r.ResolveDomains == nil || *r.ResolveDomains
	}
	return emptyLists(e), versionOf(data), nil
}

// emptyLists заменяет отсутствующие списки пустыми, чтобы в JSON были [], а не null.
func emptyLists(e Editable) Editable {
	fix := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return s
	}
	e.PublicIPServices = fix(e.PublicIPServices)
	if e.Rules == nil {
		e.Rules = []EditRule{}
	}
	for i := range e.Rules {
		r := &e.Rules[i]
		r.AllowFrom, r.Domains, r.IPs = fix(r.AllowFrom), fix(r.Domains), fix(r.IPs)
		r.IPServices = fix(r.IPServices)
		if r.Apps == nil {
			r.Apps = []EditApp{}
		}
	}
	return e
}

// Save записывает настройки целиком. Комментарии, порядок и неизвестные панели ключи
// сохраняются: правятся только сами значения. Перед записью результат проверяется как
// обычный конфиг; прежняя версия остаётся рядом в файле с расширением .bak.
func Save(path, version string, e Editable) error {
	old, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		old = nil
		if version != versionNew {
			return ErrChanged
		}
	case err != nil:
		return err
	case versionOf(old) != version:
		return ErrChanged
	}

	updated, err := applyEditable(old, e)
	if err != nil {
		return err
	}
	if old != nil {
		if err := os.WriteFile(path+".bak", old, 0o644); err != nil {
			return fmt.Errorf("не удалось сохранить резервную копию: %w", err)
		}
	} else if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, updated, 0o644)
}

func applyEditable(data []byte, e Editable) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Kind == 0 { // файла нет или он пуст
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
		doc.Content[0].HeadComment = "Настройки ipblock. Файл можно править и вручную, и в панели управления."
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("файл настроек должен быть словарём (ключ: значение)")
	}

	setText(root, "check_interval", e.CheckInterval)
	setText(root, "on_stop", e.OnStop)
	setText(root, "log_file", e.LogFile)
	setList(root, "public_ip_services", e.PublicIPServices)

	rules := mapGet(root, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		rules = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		mapSet(root, "rules", rules)
	}
	oldRules := rules.Content
	used := map[int]bool{}
	var content []*yaml.Node
	for _, r := range e.Rules {
		var node *yaml.Node
		if r.Index >= 0 && r.Index < len(oldRules) && !used[r.Index] && oldRules[r.Index].Kind == yaml.MappingNode {
			node = oldRules[r.Index]
			used[r.Index] = true
		} else {
			node = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		}
		setText(node, "name", r.Name)
		// «public» — значение по умолчанию: не дописываем его туда, где ключа не было.
		if src := strings.TrimSpace(r.IPSource); src != SourcePublic || mapGet(node, "ip_source") != nil {
			setText(node, "ip_source", src)
		}
		setList(node, "allow_from", r.AllowFrom)
		setList(node, "domains", r.Domains)
		if r.Resolve {
			mapDelete(node, "resolve_domains") // включено по умолчанию
		} else {
			mapSet(node, "resolve_domains", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "false"})
		}
		setList(node, "ips", r.IPs)
		setApps(node, r.Apps)
		setList(node, "ip_services", r.IPServices)
		content = append(content, node)
	}
	rules.Content = content

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	_ = enc.Close()

	// Результат должен быть рабочим конфигом: иначе сервис перестал бы его перечитывать.
	var check Config
	if err := yaml.Unmarshal(buf.Bytes(), &check); err != nil {
		return nil, fmt.Errorf("после правки файл не читается: %w", err)
	}
	if err := check.normalize(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// setText записывает строковое значение; пустое — убирает ключ (действует умолчание).
// У существующего значения меняется только текст: комментарий рядом с ним остаётся.
func setText(m *yaml.Node, key, val string) {
	val = strings.TrimSpace(val)
	if val == "" {
		mapDelete(m, key)
		return
	}
	if n := mapGet(m, key); n != nil && n.Kind == yaml.ScalarNode {
		if n.Value != val {
			n.Value, n.Tag, n.Style = val, "!!str", 0
		}
		return
	}
	mapSet(m, key, scalar(val))
}

// setList записывает список строк; пустой — убирает ключ. Элементы, которые были
// в списке и раньше, сохраняют свои комментарии.
func setList(m *yaml.Node, key string, values []string) {
	var clean []string
	seen := map[string]bool{}
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" && !seen[v] {
			seen[v] = true
			clean = append(clean, v)
		}
	}
	if len(clean) == 0 {
		mapDelete(m, key)
		return
	}
	seq := mapGet(m, key)
	if seq == nil || seq.Kind != yaml.SequenceNode {
		seq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		mapSet(m, key, seq)
	}
	old := map[string]*yaml.Node{}
	for _, n := range seq.Content {
		if n.Kind == yaml.ScalarNode {
			old[n.Value] = n
		}
	}
	seq.Content = nil
	seq.Style = 0 // запись в столбик: так читается и короткий, и длинный список
	for _, v := range clean {
		if n := old[v]; n != nil {
			seq.Content = append(seq.Content, n)
		} else {
			seq.Content = append(seq.Content, scalar(v))
		}
	}
}

func setApps(rule *yaml.Node, apps []EditApp) {
	var content []*yaml.Node
	for _, a := range apps {
		if strings.TrimSpace(a.Windows) == "" && strings.TrimSpace(a.Darwin) == "" {
			continue
		}
		n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		setText(n, "windows", a.Windows)
		setText(n, "darwin", a.Darwin)
		setText(n, "action", a.Action)
		content = append(content, n)
	}
	if len(content) == 0 {
		mapDelete(rule, "apps")
		return
	}
	seq := mapGet(rule, "apps")
	if seq == nil || seq.Kind != yaml.SequenceNode {
		seq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		mapSet(rule, "apps", seq)
	}
	// Программы, не изменившиеся с прошлого раза, остаются прежними узлами (с комментариями).
	for i, n := range content {
		if i < len(seq.Content) && sameApp(seq.Content[i], n) {
			content[i] = seq.Content[i]
		}
	}
	seq.Content = content
}

func sameApp(a, b *yaml.Node) bool {
	for _, k := range []string{"windows", "darwin", "action"} {
		x, y := mapGet(a, k), mapGet(b, k)
		if (x == nil) != (y == nil) || (x != nil && x.Value != y.Value) {
			return false
		}
	}
	return true
}

func mapDelete(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}
