package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func load(t *testing.T, yaml string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

// Пример, который записывает `ipblock init`, обязан загружаться без ошибок.
func TestExampleIsValid(t *testing.T) {
	c, err := load(t, string(Example))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Rules) != 1 || c.Rules[0].IPSource != SourcePublic || len(c.Rules[0].AllowMatchers) != 4 {
		t.Errorf("неожиданный разбор примера: %+v", c.Rules)
	}
	if c.CheckInterval.Duration != 20*time.Second || c.OnStop != StopLock {
		t.Errorf("интервал %v, on_stop %q", c.CheckInterval.Duration, c.OnStop)
	}
}

func TestDefaultsAndNormalization(t *testing.T) {
	c, err := load(t, `
rules:
  - allow_from: ["2001:db8::/32"]
    domains: ["https://Mail.Example.com/inbox"]
`)
	if err != nil {
		t.Fatal(err)
	}
	r := c.Rules[0]
	if r.Name != "rule-1" || r.Domains[0] != "mail.example.com" {
		t.Errorf("имя %q, домен %q", r.Name, r.Domains[0])
	}
	if !c.NeedsPublic() || c.NeedsLocal() || !c.NeedsPublicV6() {
		t.Errorf("источники IP определены неверно")
	}
	if !strings.HasSuffix(c.LogFile, "ipblock.log") {
		t.Errorf("log_file: %q", c.LogFile)
	}
}

func TestInvalidConfigs(t *testing.T) {
	cases := map[string]string{
		"нет правил":          "check_interval: 30s\n",
		"пустой allow_from":   "rules:\n  - domains: [x.com]\n",
		"нечего блокировать":  "rules:\n  - allow_from: [1.2.3.4]\n",
		"плохая маска":        "rules:\n  - allow_from: [\"10.1.*\"]\n    domains: [x.com]\n",
		"шаблон в домене":     "rules:\n  - allow_from: [1.2.3.4]\n    domains: [\"*.x.com\"]\n",
		"шаблон в ips":        "rules:\n  - allow_from: [1.2.3.4]\n    ips: [\"10.1.*.*\"]\n",
		"плохой ip_source":    "rules:\n  - allow_from: [1.2.3.4]\n    ip_source: vpn\n    domains: [x.com]\n",
		"слишком частая":      "check_interval: 1s\nrules:\n  - allow_from: [1.2.3.4]\n    domains: [x.com]\n",
		"плохой on_stop":      "on_stop: maybe\nrules:\n  - allow_from: [1.2.3.4]\n    domains: [x.com]\n",
		"повтор имени":        "rules:\n  - name: a\n    allow_from: [1.2.3.4]\n    domains: [x.com]\n  - name: a\n    allow_from: [1.2.3.4]\n    domains: [y.com]\n",
		"плохое действие":     "rules:\n  - allow_from: [1.2.3.4]\n    apps:\n      - windows: a.exe\n        darwin: a\n        action: hide\n",
		"плохая длительность": "check_interval: скоро\nrules:\n  - allow_from: [1.2.3.4]\n    domains: [x.com]\n",
	}
	for name, yaml := range cases {
		if _, err := load(t, yaml); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}
