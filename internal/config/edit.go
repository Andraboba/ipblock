package config

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// Addition — что дописать в файл настроек.
type Addition struct {
	Rule      string   // имя существующего правила; пусто — создать новое
	NewName   string   // имя нового правила
	AllowFrom []string // allow_from нового правила
	IPs       []string // адреса и подсети, которые нужно закрыть
	AppPath   string   // программа, которую нужно закрыть; пусто — не добавлять
}

// Add дописывает адреса и программу в правило (или создаёт новое), сохраняя
// комментарии и порядок остального файла. Перед записью результат проверяется
// как обычный конфиг; прежняя версия остаётся рядом в файле с расширением .bak.
func Add(path string, a Addition) error {
	old, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	updated, err := applyAddition(old, a)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".bak", old, 0o644); err != nil {
		return fmt.Errorf("не удалось сохранить резервную копию: %w", err)
	}
	return os.WriteFile(path, updated, 0o644)
}

func applyAddition(data []byte, a Addition) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Kind == 0 { // пустой файл
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("файл настроек должен быть словарём (ключ: значение)")
	}
	rules := mapGet(root, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		rules = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		mapSet(root, "rules", rules)
	}

	var rule *yaml.Node
	if a.Rule == "" {
		name := strings.TrimSpace(a.NewName)
		if name == "" {
			return nil, fmt.Errorf("не указано имя нового правила")
		}
		if len(a.AllowFrom) == 0 {
			return nil, fmt.Errorf("не указано, с каких адресов разрешён доступ (allow_from)")
		}
		rule = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		mapSet(rule, "name", scalar(name))
		mapSet(rule, "ip_source", scalar(SourcePublic))
		allow := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		seqAdd(allow, a.AllowFrom)
		mapSet(rule, "allow_from", allow)
		rules.Content = append(rules.Content, rule)
	} else {
		for i, r := range rules.Content {
			if r.Kind != yaml.MappingNode {
				continue
			}
			name := fmt.Sprintf("rule-%d", i+1) // так же называет безымянные правила normalize
			if n := mapGet(r, "name"); n != nil && n.Value != "" {
				name = n.Value
			}
			if name == a.Rule {
				rule = r
				break
			}
		}
		if rule == nil {
			return nil, fmt.Errorf("правило %q не найдено в файле настроек", a.Rule)
		}
	}

	if len(a.IPs) > 0 {
		ips := mapGet(rule, "ips")
		if ips == nil || ips.Kind != yaml.SequenceNode {
			ips = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			mapSet(rule, "ips", ips)
		}
		seqAdd(ips, a.IPs)
	}
	if a.AppPath != "" {
		apps := mapGet(rule, "apps")
		if apps == nil || apps.Kind != yaml.SequenceNode {
			apps = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			mapSet(rule, "apps", apps)
		}
		key := "darwin"
		if runtime.GOOS == "windows" {
			key = "windows"
		}
		known := false
		for _, app := range apps.Content {
			if v := mapGet(app, key); v != nil && strings.EqualFold(v.Value, a.AppPath) {
				known = true
			}
		}
		if !known {
			app := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			mapSet(app, key, scalar(a.AppPath))
			apps.Content = append(apps.Content, app)
		}
	}

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

func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func mapSet(m *yaml.Node, key string, val *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = val
			return
		}
	}
	m.Content = append(m.Content, scalar(key), val)
}

// seqAdd дописывает в список значения, которых в нём ещё нет.
func seqAdd(seq *yaml.Node, values []string) {
	have := map[string]bool{}
	for _, n := range seq.Content {
		have[n.Value] = true
	}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || have[v] {
			continue
		}
		have[v] = true
		seq.Content = append(seq.Content, scalar(v))
	}
}

func scalar(s string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
}
