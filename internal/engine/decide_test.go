package engine

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ipblock/internal/config"
	"ipblock/internal/detect"
)

const (
	svcA = "https://a.example/ip"
	svcB = "https://b.example/ip"
	svcC = "https://c.example/ip"
)

func loadCfg(t *testing.T, yaml string) *config.Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ans(svc, addr string) detect.Answer {
	return detect.Answer{Service: svc, Addr: netip.MustParseAddr(addr), Local: netip.MustParseAddr("10.8.0.2")}
}

func failed(svc string) detect.Answer { return detect.Answer{Service: svc, Err: "timeout"} }

func stale(a detect.Answer) detect.Answer { a.Stale = true; return a }

const baseCfg = `
public_ip_services: [` + svcA + `, ` + svcB + `, ` + svcC + `]
rules:
  - name: только чистый выход
    allow_from: [203.0.113.17]
    ips: [192.0.2.1]
  - name: оба выхода
    allow_from: [203.0.113.17, 198.51.100.0/24]
    ips: [192.0.2.2]
  - name: свой сервис проверки
    allow_from: [203.0.113.17]
    ip_services: [` + svcA + `]
    ips: [192.0.2.3]
`

// VPN ведёт один сервис проверки через один сервер, остальные — через другой.
// Раньше сервисы опрашивались по очереди, и доступ открывался и закрывался сам собой.
func TestSplitRoutingIsStable(t *testing.T) {
	cfg := loadCfg(t, baseCfg)
	answers := []detect.Answer{ans(svcA, "203.0.113.17"), ans(svcB, "198.51.100.42"), ans(svcC, "198.51.100.42")}

	// Порядок ответов не должен влиять на решение.
	for _, order := range [][]detect.Answer{answers, {answers[2], answers[0], answers[1]}} {
		snap := Decide(cfg, order, nil)
		if snap.Rules[0].Allowed {
			t.Error("правило с одним разрешённым адресом открыто, хотя часть сервисов видит другой адрес")
		}
		if !strings.Contains(snap.Rules[0].Note, "разные адреса") || !strings.Contains(snap.Rules[0].Note, "198.51.100.42") {
			t.Errorf("нет пояснения, почему закрыто: %q", snap.Rules[0].Note)
		}
		if !snap.Rules[1].Allowed || snap.Rules[1].Note != "" {
			t.Errorf("правило, где разрешены оба выхода, должно быть открыто: %+v", snap.Rules[1])
		}
		if !snap.Rules[2].Allowed || snap.Rules[2].AllowedLocal[0].String() != "10.8.0.2" {
			t.Errorf("правило со своим сервисом проверки должно быть открыто: %+v", snap.Rules[2])
		}
		if snap.PublicAddrs() != "203.0.113.17, 198.51.100.42" && snap.PublicAddrs() != "198.51.100.42, 203.0.113.17" {
			t.Errorf("PublicAddrs = %q", snap.PublicAddrs())
		}
	}
}

func TestAllServicesAgree(t *testing.T) {
	cfg := loadCfg(t, baseCfg)
	open := Decide(cfg, []detect.Answer{ans(svcA, "203.0.113.17"), ans(svcB, "203.0.113.17"), failed(svcC)}, nil)
	for i, r := range open.Rules {
		if !r.Allowed {
			t.Errorf("правило %d должно быть открыто: все ответившие сервисы видят разрешённый адрес", i)
		}
	}
	home := Decide(cfg, []detect.Answer{ans(svcA, "192.0.2.99"), ans(svcB, "192.0.2.99"), ans(svcC, "192.0.2.99")}, nil)
	for i, r := range home.Rules {
		if r.Allowed {
			t.Errorf("правило %d открыто с неразрешённого адреса", i)
		}
		if r.Note != "" {
			t.Errorf("правило %d: пояснение о разных адресах не нужно, когда адрес один: %q", i, r.Note)
		}
	}
}

func TestNoAnswersMeansClosed(t *testing.T) {
	cfg := loadCfg(t, baseCfg)
	snap := Decide(cfg, []detect.Answer{failed(svcA), failed(svcB), failed(svcC)}, nil)
	for i, r := range snap.Rules {
		if r.Allowed {
			t.Errorf("правило %d открыто, хотя ни один сервис не ответил", i)
		}
	}
	if snap.PublicErr == "" {
		t.Error("нет сообщения о том, что внешний IP не определён")
	}
}

// Недавний ответ сервиса, который сейчас молчит, может удержать доступ закрытым, но не открыть его.
func TestStaleAnswers(t *testing.T) {
	cfg := loadCfg(t, baseCfg)

	// Сервис B недавно видел неразрешённый адрес и сейчас не ответил: доступ остаётся закрытым.
	keepClosed := Decide(cfg, []detect.Answer{ans(svcA, "203.0.113.17"), stale(ans(svcB, "198.51.100.42")), failed(svcC)}, nil)
	if keepClosed.Rules[0].Allowed {
		t.Error("доступ открылся только потому, что сервис с неразрешённым адресом перестал отвечать")
	}

	// Все свежие ответы пропали, остались только недавние разрешённые: открывать нельзя.
	onlyStale := Decide(cfg, []detect.Answer{stale(ans(svcA, "203.0.113.17")), failed(svcB), failed(svcC)}, nil)
	for i, r := range onlyStale.Rules {
		if r.Allowed {
			t.Errorf("правило %d открыто по устаревшему ответу", i)
		}
	}
}

func TestLocalAndAnySources(t *testing.T) {
	cfg := loadCfg(t, `
public_ip_services: [`+svcA+`]
rules:
  - name: по локальному
    ip_source: local
    allow_from: [10.8.0.0/24]
    ips: [192.0.2.1]
  - name: любой
    ip_source: any
    allow_from: [203.0.113.0/24, 10.8.0.0/24]
    ips: [192.0.2.2]
`)
	locals := []netip.Addr{netip.MustParseAddr("192.168.1.5"), netip.MustParseAddr("10.8.0.7")}
	snap := Decide(cfg, []detect.Answer{ans(svcA, "192.0.2.99")}, locals)
	if !snap.Rules[0].Allowed || snap.Rules[0].AllowedLocal[0].String() != "10.8.0.7" {
		t.Errorf("правило по локальному адресу: %+v", snap.Rules[0])
	}
	// Внешний адрес не разрешён, но адрес VPN-адаптера подходит: открыто только для него.
	if !snap.Rules[1].Allowed || len(snap.Rules[1].AllowedLocal) != 1 || snap.Rules[1].AllowedLocal[0].String() != "10.8.0.7" {
		t.Errorf("правило any: %+v", snap.Rules[1])
	}
	none := Decide(cfg, []detect.Answer{ans(svcA, "192.0.2.99")}, locals[:1])
	if none.Rules[0].Allowed || none.Rules[1].Allowed {
		t.Errorf("без подходящих адресов оба правила должны быть закрыты: %+v", none.Rules)
	}
}

func TestMemoryKeepsClosedAndForgetsOnLock(t *testing.T) {
	e := &Engine{}
	first := e.withMemory([]detect.Answer{ans(svcA, "203.0.113.17"), ans(svcB, "198.51.100.42")})
	if first[0].Stale || first[1].Stale {
		t.Fatal("свежие ответы помечены устаревшими")
	}
	second := e.withMemory([]detect.Answer{ans(svcA, "203.0.113.17"), failed(svcB)})
	if !second[1].Stale || second[1].Addr.String() != "198.51.100.42" {
		t.Errorf("молчащему сервису не подставлен недавний ответ: %+v", second[1])
	}
	e.memory = nil // так делает lock при смене сети
	third := e.withMemory([]detect.Answer{ans(svcA, "203.0.113.17"), failed(svcB)})
	if third[1].OK() {
		t.Errorf("после смены сети прежний ответ должен быть забыт: %+v", third[1])
	}
}
