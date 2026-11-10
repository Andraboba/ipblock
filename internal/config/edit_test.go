package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAddToExistingRuleKeepsComments(t *testing.T) {
	p := writeTemp(t, string(Example))
	app := `C:\Program Files\Mail\mail.exe`
	if runtime.GOOS != "windows" {
		app = "/Applications/Mail.app"
	}
	err := Add(p, Addition{
		Rule:    "рабочая почта",
		IPs:     []string{"198.51.100.7", "192.0.2.50", "198.51.100.7", " 203.0.113.0/24 "},
		AppPath: app,
	})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(p)
	text := string(out)

	// Комментарии и прежние значения на месте.
	for _, want := range []string{
		"# Настройки ipblock.",
		"# Рабочая почта открывается только из офиса.",
		"# один адрес",
		"mail.example.com",
		"192.0.2.128/25",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("потеряно %q", want)
		}
	}

	c, err := Load(p)
	if err != nil {
		t.Fatalf("после правки конфиг не загружается: %v\n%s", err, text)
	}
	r := c.Rules[0]
	wantIPs := []string{"192.0.2.50", "192.0.2.128/25", "198.51.100.7", "203.0.113.0/24"}
	if strings.Join(r.IPs, " ") != strings.Join(wantIPs, " ") {
		t.Errorf("ips = %v, ожидалось %v", r.IPs, wantIPs)
	}
	if len(r.Apps) != 2 || r.Apps[1].Path() != app {
		t.Errorf("apps = %+v", r.Apps)
	}

	// Повторное добавление того же ничего не меняет.
	if err := Add(p, Addition{Rule: "рабочая почта", IPs: []string{"198.51.100.7"}, AppPath: app}); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(p)
	if string(again) != text {
		t.Errorf("повторное добавление изменило файл")
	}

	// Резервная копия хранит предыдущую версию.
	if bak, err := os.ReadFile(p + ".bak"); err != nil || string(bak) != text {
		t.Errorf("резервная копия не совпадает с предыдущей версией (ошибка: %v)", err)
	}
}

func TestAddNewRule(t *testing.T) {
	p := writeTemp(t, "check_interval: 20s\nrules:\n  - name: старое\n    allow_from: [10.0.0.1]\n    domains: [x.example.com]\n")
	err := Add(p, Addition{NewName: "новое", AllowFrom: []string{"203.0.113.0/24"}, IPs: []string{"198.51.100.7"}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Rules) != 2 || c.Rules[1].Name != "новое" || c.Rules[1].IPs[0] != "198.51.100.7" || c.Rules[1].AllowFrom[0] != "203.0.113.0/24" {
		t.Errorf("правила: %+v", c.Rules)
	}
	if c.Rules[0].Domains[0] != "x.example.com" {
		t.Errorf("старое правило испорчено: %+v", c.Rules[0])
	}
}

func TestAddRejectsBadInput(t *testing.T) {
	orig := "rules:\n  - name: a\n    allow_from: [10.0.0.1]\n    domains: [x.example.com]\n"
	cases := map[string]Addition{
		"нет такого правила":      {Rule: "нет", IPs: []string{"1.2.3.4"}},
		"неверный адрес":          {Rule: "a", IPs: []string{"не адрес"}},
		"новое без имени":         {AllowFrom: []string{"1.2.3.4"}, IPs: []string{"1.2.3.4"}},
		"новое без allow_from":    {NewName: "b", IPs: []string{"1.2.3.4"}},
		"новое с занятым именем":  {NewName: "a", AllowFrom: []string{"1.2.3.4"}, IPs: []string{"1.2.3.4"}},
		"новое, нечего закрывать": {NewName: "b", AllowFrom: []string{"1.2.3.4"}},
	}
	for name, a := range cases {
		p := writeTemp(t, orig)
		if err := Add(p, a); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
		// Файл при ошибке не тронут.
		if now, _ := os.ReadFile(p); string(now) != orig {
			t.Errorf("%s: файл изменён несмотря на ошибку", name)
		}
	}
}
