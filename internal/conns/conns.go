// Package conns показывает, с какими адресами сейчас соединены процессы.
//
// Видны только TCP-соединения: у UDP (в том числе QUIC) система не хранит
// адрес получателя. На практике программа почти всегда обращается к тому же
// серверу и по TCP, так что адрес всё равно попадает в список.
package conns

import "net/netip"

// Conn — одно установленное или устанавливаемое соединение.
type Conn struct {
	PID       int
	Remote    netip.AddrPort
	LocalPort uint16
}

// keep отбрасывает то, что не является обращением к внешнему серверу.
func keep(remote netip.Addr) bool {
	return remote.IsValid() && !remote.IsUnspecified() && !remote.IsLoopback() &&
		!remote.IsLinkLocalUnicast() && !remote.IsMulticast()
}
