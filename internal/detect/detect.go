// Package detect определяет текущие IP-адреса компьютера.
package detect

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Answer — ответ одного сервиса на вопрос «с какого адреса я пришёл».
//
// Сервисы опрашиваются все сразу, а не по очереди: VPN может вести трафик к разным
// сайтам через разные серверы, и тогда разные сервисы видят разные адреса. Если
// спрашивать по одному, внешний IP «прыгал» бы от проверки к проверке.
type Answer struct {
	Service string     `json:"service"`
	V6      bool       `json:"v6,omitempty"`
	Addr    netip.Addr `json:"addr"` // внешний адрес; пустой, если сервис не ответил
	// Локальный адрес, с которого шёл запрос. Доступ открывается только для него:
	// соединение через другой сетевой интерфейс проверку не проходило.
	Local netip.Addr `json:"local"`
	Err   string     `json:"error,omitempty"`
	// Stale — сервис сейчас не ответил, показан его недавний ответ. Такой ответ
	// может только закрыть доступ, но не открыть.
	Stale bool `json:"stale,omitempty"`
}

// OK сообщает, есть ли в ответе адрес.
func (a Answer) OK() bool { return a.Addr.IsValid() }

// Host — короткое имя сервиса для показа человеку.
func (a Answer) Host() string { return Host(a.Service) }

// Host возвращает имя узла из адреса сервиса.
func Host(service string) string {
	if u, err := url.Parse(service); err == nil && u.Host != "" {
		return u.Host
	}
	return service
}

// Ask опрашивает все сервисы одновременно по IPv4 (или IPv6, если v6).
// Ответы идут в том же порядке, что и сервисы.
func Ask(ctx context.Context, services []string, v6 bool) []Answer {
	network := "tcp4"
	if v6 {
		network = "tcp6"
	}
	out := make([]Answer, len(services))
	var wg sync.WaitGroup
	for i, svc := range services {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a := Answer{Service: svc, V6: v6}
			addr, local, err := fetch(ctx, network, svc)
			if err != nil && ctx.Err() == nil {
				// Одна повторная попытка: случайный сбой сервиса не должен закрывать доступ.
				time.Sleep(300 * time.Millisecond)
				addr, local, err = fetch(ctx, network, svc)
			}
			if err != nil {
				a.Err = err.Error()
			} else {
				a.Addr, a.Local = addr, local
			}
			out[i] = a
		}()
	}
	wg.Wait()
	return out
}

func fetch(ctx context.Context, network, service string) (addr, local netip.Addr, err error) {
	var mu sync.Mutex
	d := &net.Dialer{Timeout: 4 * time.Second}
	tr := &http.Transport{
		// Без прокси и строго по одному семейству адресов: нужен адрес,
		// под которым машину видно напрямую.
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, target string) (net.Conn, error) {
			c, err := d.DialContext(ctx, network, target)
			if err == nil {
				if ta, ok := c.LocalAddr().(*net.TCPAddr); ok {
					mu.Lock()
					local = ta.AddrPort().Addr().Unmap().WithZone("")
					mu.Unlock()
				}
			}
			return c, err
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Timeout: 5 * time.Second, Transport: tr}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, service, nil)
	if err != nil {
		return addr, local, err
	}
	req.Header.Set("User-Agent", "ipblock")
	resp, err := client.Do(req)
	if err != nil {
		return addr, local, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return addr, local, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return addr, local, err
	}
	ip, err := ParseBody(string(body))
	if err != nil {
		return addr, local, err
	}
	if ip.Is4() != (network == "tcp4") {
		return addr, local, fmt.Errorf("адрес %s не того семейства", ip)
	}
	mu.Lock()
	defer mu.Unlock()
	if !local.IsValid() {
		return addr, local, fmt.Errorf("не удалось определить локальный адрес соединения")
	}
	return ip, local, nil
}

// ParseBody достаёт адрес из ответа сервиса. Понимает два вида ответа:
// сам адрес одной строкой и набор строк «ключ=значение» со строкой ip=… (так
// отвечает /cdn-cgi/trace у сайтов за Cloudflare).
func ParseBody(body string) (netip.Addr, error) {
	text := strings.TrimSpace(body)
	if ip, err := netip.ParseAddr(text); err == nil {
		return ip.Unmap(), nil
	}
	for _, line := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "ip="); ok {
			if ip, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
				return ip.Unmap(), nil
			}
		}
	}
	if len(text) > 40 {
		text = text[:40] + "…"
	}
	return netip.Addr{}, fmt.Errorf("неожиданный ответ %q", text)
}

// LocalIPs возвращает адреса всех поднятых интерфейсов, кроме loopback и link-local.
func LocalIPs() ([]netip.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			pfx, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			ip := pfx.Addr().Unmap().WithZone("")
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			out = append(out, ip)
		}
	}
	return out, nil
}
