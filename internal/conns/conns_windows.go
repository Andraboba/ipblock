package conns

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetExtendedTcpTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

const (
	tcpTableOwnerPidAll = 5 // TCP_TABLE_OWNER_PID_ALL
	stateListen         = 2 // MIB_TCP_STATE_LISTEN
)

// Snapshot возвращает текущие TCP-соединения всех процессов.
func Snapshot() ([]Conn, error) {
	var out []Conn

	// MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid — по 4 байта.
	buf, err := table(windows.AF_INET)
	if err != nil {
		return nil, err
	}
	for _, row := range rows(buf, 24) {
		if binary.LittleEndian.Uint32(row[0:]) == stateListen {
			continue
		}
		remote := netip.AddrFrom4([4]byte(row[12:16]))
		if keep(remote) {
			out = append(out, Conn{
				PID:       int(binary.LittleEndian.Uint32(row[20:])),
				Remote:    netip.AddrPortFrom(remote, binary.BigEndian.Uint16(row[16:])),
				LocalPort: binary.BigEndian.Uint16(row[8:]),
			})
		}
	}

	// MIB_TCP6ROW_OWNER_PID: localAddr[16], localScope, localPort, remoteAddr[16],
	// remoteScope, remotePort, state, pid.
	buf, err = table(windows.AF_INET6)
	if err != nil {
		return out, nil // IPv6 может быть выключен
	}
	for _, row := range rows(buf, 56) {
		if binary.LittleEndian.Uint32(row[48:]) == stateListen {
			continue
		}
		remote := netip.AddrFrom16([16]byte(row[24:40])).Unmap()
		if keep(remote) {
			out = append(out, Conn{
				PID:       int(binary.LittleEndian.Uint32(row[52:])),
				Remote:    netip.AddrPortFrom(remote, binary.BigEndian.Uint16(row[44:])),
				LocalPort: binary.BigEndian.Uint16(row[20:]),
			})
		}
	}
	return out, nil
}

// table читает таблицу соединений целиком; размер заранее неизвестен и может вырасти между вызовами.
func table(family uint32) ([]byte, error) {
	size := uint32(64 * 1024)
	for range 6 {
		buf := make([]byte, size)
		r, _, _ := procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
			0, uintptr(family), tcpTableOwnerPidAll, 0)
		switch syscall.Errno(r) {
		case 0:
			return buf, nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			size += 16 * 1024
		default:
			return nil, syscall.Errno(r)
		}
	}
	return nil, windows.ERROR_INSUFFICIENT_BUFFER
}

// rows режет таблицу на строки: в начале 4 байта — число строк, дальше строки подряд.
func rows(buf []byte, rowSize int) [][]byte {
	n := int(binary.LittleEndian.Uint32(buf))
	out := make([][]byte, 0, n)
	for i := range n {
		off := 4 + i*rowSize
		if off+rowSize > len(buf) {
			break
		}
		out = append(out, buf[off:off+rowSize])
	}
	return out
}
