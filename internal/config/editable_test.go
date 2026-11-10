package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Сохранение без изменений не должно ничего терять: ни значений, ни комментариев.
func TestSaveUnchangedKeepsEverything(t *testing.T) {
	p := writeTemp(t, string(Example))
	before, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	e, ver, err := LoadEditable(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(p, ver, e); err != nil {
		t.Fatal(err)
	}
	after, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(p)
	text := string(out)
	for _, want := range []string{
		"# Настройки ipblock.",
		"# Как часто перепроверять IP",
		"# Рабочая почта открывается только из офиса.",
		"# один адрес",
		"# шаблон по октетам",
		"# Сайты. Каждый поддомен",
		"# Программы.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("потерян комментарий %q", want)
		}
	}
	a, b := before.Rules[0], after.Rules[0]
	if strings.Join(a.AllowFrom, "|") != strings.Join(b.AllowFrom, "|") ||
		strings.Join(a.Domains, "|") != strings.Join(b.Domains, "|") ||
		strings.Join(a.IPs, "|") != strings.Join(b.IPs, "|") ||
		len(a.Apps) != len(b.Apps) || a.Apps[0] != b.Apps[0] ||
		before.CheckInterval != after.CheckInterval || before.OnStop != after.OnStop {
		t.Errorf("значения изменились:\nбыло  %+v\nстало %+v", a, b)
	}

	// Второе сохранение даёт тот же файл байт в байт.
	e2, ver2, _ := LoadEditable(p)
	if err := Save(p, ver2, e2); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(p); string(again) != text {
		t.Error("повторное сохранение без изменений изменило файл")
	}
}

func TestSaveEditsAddsAndDeletes(t *testing.T) {
	p := writeTemp(t, `# шапка
check_interval: 30s # интервал
log_file: custom.log
rules:
  # первое
  - name: первое
    allow_from:
      - 10.0.0.1 # офис
      - 10.0.0.2
    domains: [a.example.com]
  # второе
  - name: второе
    ip_source: local
    allow_from: [192.168.0.0/16]
    ips: [198.51.100.1]
`)
	e, ver, err := LoadEditable(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Rules) != 2 || e.Rules[1].Index != 1 || !e.Rules[0].Resolve || e.CheckInterval != "30s" {
		t.Fatalf("прочитано неверно: %+v", e)
	}

	// Меняем общие настройки, правим второе правило, первое удаляем, добавляем новое.
	e.CheckInterval = "10s"
	e.OnStop = "clear"
	second := e.Rules[1]
	second.Name = "второе (новое имя)"
	second.AllowFrom = []string{"192.168.0.0/16", "10.8.0.0/24"}
	second.Domains = []string{"b.example.com"}
	second.Resolve = false
	second.Apps = []EditApp{{Windows: `C:\Apps\x.exe`, Darwin: "/Applications/X.app", Action: "kill"}, {}}
	e.Rules = []EditRule{second, {Index: -1, Name: "третье", IPSource: "public", AllowFrom: []string{"203.0.113.0/24"}, IPs: []string{"192.0.2.1"}, Resolve: true}}
	if err := Save(p, ver, e); err != nil {
		t.Fatal(err)
	}

	out, _ := os.ReadFile(p)
	text := string(out)
	for _, want := range []string{"# шапка", "# интервал", "# второе", "log_file: custom.log"} {
		if !strings.Contains(text, want) {
			t.Errorf("потеряно %q в:\n%s", want, text)
		}
	}
	for _, gone := range []string{"первое", "a.example.com", "# офис"} {
		if strings.Contains(text, gone) {
			t.Errorf("удалённое правило оставило след %q в:\n%s", gone, text)
		}
	}

	c, err := Load(p)
	if err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	if c.CheckInterval.Seconds() != 10 || c.OnStop != StopClear || filepath.Base(c.LogFile) != "custom.log" {
		t.Errorf("общие настройки: %v %q %q", c.CheckInterval.Duration, c.OnStop, c.LogFile)
	}
	if len(c.Rules) != 2 {
		t.Fatalf("правил %d:\n%s", len(c.Rules), text)
	}
	r := c.Rules[0]
	if r.Name != "второе (новое имя)" || r.IPSource != SourceLocal || len(r.AllowFrom) != 2 ||
		r.Domains[0] != "b.example.com" || r.Resolve() || r.IPs[0] != "198.51.100.1" ||
		len(r.Apps) != 1 || r.Apps[0].Windows != `C:\Apps\x.exe` || r.Apps[0].Action != "kill" {
		t.Errorf("второе правило: %+v", r)
	}
	if n := c.Rules[1]; n.Name != "третье" || n.IPSource != SourcePublic || n.IPs[0] != "192.0.2.1" || !n.Resolve() {
		t.Errorf("новое правило: %+v", n)
	}
	// «public» по умолчанию не дописывается в новое правило.
	if strings.Contains(text, "ip_source: public") {
		t.Errorf("лишний ip_source: public:\n%s", text)
	}
}

func TestSaveRejectsStaleAndInvalid(t *testing.T) {
	orig := "rules:\n  - name: a\n    allow_from: [10.0.0.1]\n    domains: [x.example.com]\n"
	p := writeTemp(t, orig)
	e, ver, _ := LoadEditable(p)

	// Файл изменили другим способом после чтения.
	if err := os.WriteFile(p, []byte(orig+"# правка руками\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Save(p, ver, e); !errors.Is(err, ErrChanged) {
		t.Errorf("ожидалась ErrChanged, получено %v", err)
	}

	// Неверные данные не записываются.
	e, ver, _ = LoadEditable(p)
	current, _ := os.ReadFile(p)
	bad := e
	bad.Rules = []EditRule{{Index: 0, Name: "a", AllowFrom: []string{"10.1.*"}, Domains: []string{"x.example.com"}, Resolve: true}}
	if err := Save(p, ver, bad); err == nil {
		t.Error("неверная маска должна быть отклонена")
	}
	bad = e
	bad.CheckInterval = "1s"
	if err := Save(p, ver, bad); err == nil {
		t.Error("слишком частая проверка должна быть отклонена")
	}
	bad = e
	bad.Rules = nil
	if err := Save(p, ver, bad); err == nil {
		t.Error("конфиг без правил должен быть отклонён")
	}
	if now, _ := os.ReadFile(p); string(now) != string(current) {
		t.Error("файл изменён несмотря на ошибку")
	}
}

func TestSaveCreatesMissingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "config.yaml")
	e, ver, err := LoadEditable(p)
	if err != nil || ver != versionNew || len(e.Rules) != 0 {
		t.Fatalf("e=%+v ver=%q err=%v", e, ver, err)
	}
	e.Rules = []EditRule{{Index: -1, Name: "почта", AllowFrom: []string{"203.0.113.0/24"}, Domains: []string{"mail.example.com"}, Resolve: true}}
	if err := Save(p, ver, e); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil || c.Rules[0].Name != "почта" {
		t.Fatalf("c=%+v err=%v", c, err)
	}
	// Повторное сохранение со старой версией «файла нет» отклоняется: файл уже есть.
	if err := Save(p, ver, e); !errors.Is(err, ErrChanged) {
		t.Errorf("ожидалась ErrChanged, получено %v", err)
	}
}
