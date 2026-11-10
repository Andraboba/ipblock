// Package netwatch сообщает об изменениях сети: появился или исчез адрес,
// сменился шлюз по умолчанию. По такому сигналу сервис сразу закрывает доступ
// и только потом перепроверяет IP.
package netwatch

import (
	"context"
	"encoding/binary"
	"net"
	"sort"
	"strings"
	"syscall"
)

// Watch читает сообщения ядра из маршрутного сокета и шлёт сигнал в ch (без
// блокировки: если сигнал уже ждёт обработки, новый не нужен).
func Watch(ctx context.Context, ch chan<- struct{}) error {
	fd, err := syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = syscall.Close(fd)
	}()
	go func() {
		buf := make([]byte, 8192)
		last := fingerprint()
		for {
			n, err := syscall.Read(fd, buf)
			if err != nil {
				if err == syscall.EINTR {
					continue
				}
				return
			}
			changed := false
			for msg := buf[:n]; len(msg) >= 16; {
				l := int(binary.LittleEndian.Uint16(msg[0:2]))
				if l < 4 || l > len(msg) {
					break
				}
				if relevant(msg[:l], &last) {
					changed = true
				}
				msg = msg[l:]
			}
			if changed {
				select {
				case ch <- struct{}{}:
				default:
				}
			}
		}
	}()
	return nil
}

// relevant решает, означает ли сообщение смену сети.
// Заголовки rt_msghdr, ifa_msghdr и if_msghdr начинаются одинаково:
// длина (2 байта), версия (1), тип (1), ...; у rt_msghdr флаги лежат по смещению 8.
func relevant(msg []byte, last *string) bool {
	switch msg[3] {
	case syscall.RTM_NEWADDR, syscall.RTM_DELADDR:
		*last = fingerprint()
		return true
	case syscall.RTM_IFINFO:
		// Приходит и без реальных изменений, поэтому сверяем состав интерфейсов и адресов.
		fp := fingerprint()
		if fp == *last {
			return false
		}
		*last = fp
		return true
	case syscall.RTM_ADD, syscall.RTM_DELETE, syscall.RTM_CHANGE:
		if len(msg) < 12 {
			return false
		}
		// Только сетевые маршруты через шлюз (в их числе маршрут по умолчанию).
		// Записи о соседях по сети (ARP) — тоже «маршруты», но они хостовые.
		flags := binary.LittleEndian.Uint32(msg[8:12])
		return flags&syscall.RTF_GATEWAY != 0 && flags&syscall.RTF_HOST == 0
	}
	return false
}

// fingerprint — поднятые интерфейсы с их адресами одной строкой.
func fingerprint() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var parts []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		s := ifc.Name + "/" + ifc.Flags.String()
		for _, a := range addrs {
			s += "," + a.String()
		}
		parts = append(parts, s)
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}
