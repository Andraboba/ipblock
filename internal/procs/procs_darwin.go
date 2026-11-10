// Package procs завершает процессы запрещённых приложений.
package procs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

var (
	mu sync.Mutex
	// Процессы, которым уже отправлен SIGTERM: при следующей встрече получат SIGKILL.
	asked = map[int]bool{}
)

// Kill завершает процессы, чей исполняемый файл совпадает с одной из целей.
// Цель — путь к .app, путь к исполняемому файлу либо только имя процесса.
// Сначала отправляется SIGTERM (приложение успевает сохранить данные),
// при следующем вызове — SIGKILL. Возвращает описания завершённых процессов.
func Kill(targets []string) []string {
	if len(targets) == 0 {
		return nil
	}
	out, err := exec.Command("ps", "-axo", "pid=,comm=").Output()
	if err != nil {
		return nil
	}

	mu.Lock()
	defer mu.Unlock()
	alive := map[int]bool{}
	self := os.Getpid()

	var killed []string
	for _, line := range strings.Split(string(out), "\n") {
		pidStr, comm, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(pidStr)
		if err != nil || pid == self || pid <= 1 {
			continue
		}
		comm = strings.TrimSpace(comm)
		if !matches(comm, targets) {
			continue
		}
		alive[pid] = true
		sig := syscall.SIGTERM
		if asked[pid] {
			sig = syscall.SIGKILL
		}
		if syscall.Kill(pid, sig) == nil {
			if !asked[pid] {
				killed = append(killed, filepath.Base(comm))
			}
			asked[pid] = true
		}
	}
	for pid := range asked {
		if !alive[pid] {
			delete(asked, pid)
		}
	}
	return killed
}

func matches(comm string, targets []string) bool {
	for _, t := range targets {
		t = strings.TrimRight(t, "/")
		switch {
		case strings.HasSuffix(t, ".app"):
			if strings.HasPrefix(comm, t+"/") {
				return true
			}
		case strings.Contains(t, "/"):
			if comm == t {
				return true
			}
		default:
			if filepath.Base(comm) == t {
				return true
			}
		}
	}
	return false
}
