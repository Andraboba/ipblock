// Package procs завершает процессы запрещённых приложений.
package procs

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type target struct {
	path     string // очищенный путь либо имя файла
	nameOnly bool   // задано только имя файла, без пути
	dir      bool   // задана папка: подходят все программы внутри неё
}

// Kill завершает процессы, чей исполняемый файл совпадает с одной из целей.
// Цель — полный путь к .exe, папка (все программы в ней) либо только имя файла
// (например "outlook.exe"). Возвращает имена завершённых процессов.
func Kill(targets []string) []string {
	if len(targets) == 0 {
		return nil
	}
	ts := make([]target, 0, len(targets))
	for _, t := range targets {
		if !strings.ContainsAny(t, `\/`) {
			ts = append(ts, target{path: t, nameOnly: true})
			continue
		}
		t = filepath.Clean(t)
		fi, err := os.Stat(t)
		isDir := err == nil && fi.IsDir()
		ts = append(ts, target{path: t, dir: isDir})
	}

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)

	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	self := windows.GetCurrentProcessId()

	var killed []string
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if e.ProcessID == 0 || e.ProcessID == self {
			continue
		}
		name := windows.UTF16ToString(e.ExeFile[:])
		if !matches(name, e.ProcessID, ts) {
			continue
		}
		h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, e.ProcessID)
		if err != nil {
			continue
		}
		if windows.TerminateProcess(h, 1) == nil {
			killed = append(killed, name)
		}
		windows.CloseHandle(h)
	}
	return killed
}

func matches(name string, pid uint32, targets []target) bool {
	// Полный путь процесса узнаём только когда без него не обойтись: это отдельный
	// системный вызов на каждый процесс.
	full, asked := "", false
	fullPath := func() string {
		if !asked {
			full, asked = filepath.Clean(imagePath(pid)), true
		}
		return full
	}
	for _, t := range targets {
		switch {
		case t.nameOnly:
			if strings.EqualFold(name, t.path) {
				return true
			}
		case t.dir:
			if p := fullPath(); len(p) > len(t.path)+1 && strings.EqualFold(p[:len(t.path)+1], t.path+`\`) {
				return true
			}
		default:
			if strings.EqualFold(name, filepath.Base(t.path)) && strings.EqualFold(fullPath(), t.path) {
				return true
			}
		}
	}
	return false
}

func imagePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}
