package procs

import (
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// List возвращает все запущенные процессы.
func List() ([]Proc, error) {
	out, err := exec.Command("ps", "-axo", "pid=,ppid=,comm=").Output()
	if err != nil {
		return nil, err
	}
	var list []Proc
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		pid, err1 := strconv.Atoi(f[0])
		ppid, err2 := strconv.Atoi(f[1])
		if err1 != nil || err2 != nil {
			continue
		}
		// Путь может содержать пробелы: берём всё после второго поля.
		rest := strings.TrimSpace(line)
		rest = strings.TrimSpace(strings.TrimPrefix(rest, f[0]))
		rest = strings.TrimSpace(strings.TrimPrefix(rest, f[1]))
		list = append(list, Proc{PID: pid, PPID: ppid, Name: filepath.Base(rest), Path: rest})
	}
	return list, nil
}
