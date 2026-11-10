package conns

import (
	"net/netip"
	"strconv"
	"strings"
)

// ParseLsof разбирает вывод `lsof -nP -iTCP -F pn` (macOS). Формат — по строке на поле:
// строка p<pid> начинает процесс, строка n<адреса> описывает сокет, например
// n192.168.1.5:54321->203.0.113.7:443 или n[::1]:54321->[2001:db8::1]:443.
func ParseLsof(out string) []Conn {
	var list []Conn
	pid := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(line[1:])
		case 'n':
			local, remote, ok := strings.Cut(line[1:], "->")
			if !ok {
				continue // слушающий сокет
			}
			r, err := netip.ParseAddrPort(remote)
			if err != nil {
				continue
			}
			c := Conn{PID: pid, Remote: netip.AddrPortFrom(r.Addr().Unmap(), r.Port())}
			if l, err := netip.ParseAddrPort(local); err == nil {
				c.LocalPort = l.Port()
			}
			if keep(c.Remote.Addr()) {
				list = append(list, c)
			}
		}
	}
	return list
}
