package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// IsAdmin сообщает, запущена ли программа с правами администратора.
func IsAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// Interactive — запущены в консоли, а не диспетчером служб.
func Interactive() bool {
	is, err := svc.IsWindowsService()
	return err != nil || !is
}

// BinaryPath — куда install кладёт программу.
func BinaryPath() string {
	base := os.Getenv("ProgramFiles")
	if base == "" {
		base = `C:\Program Files`
	}
	return filepath.Join(base, "ipblock", "ipblock.exe")
}

// Install регистрирует (или обновляет) службу с автозапуском и запускает её.
func Install(cfgPath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	// Сначала останавливаем старую службу: иначе её .exe занят и не перезапишется.
	existing, _ := m.OpenService(Name)
	if existing != nil {
		defer existing.Close()
		if err := stopAndWait(existing); err != nil {
			return err
		}
	}

	exe := BinaryPath()
	if err := copySelf(exe); err != nil {
		return err
	}

	s := existing
	if s == nil {
		s, err = m.CreateService(Name, exe, mgr.Config{
			DisplayName: "ipblock",
			Description: "Открывает доступ к заданным сайтам, адресам и программам только с разрешённых IP.",
			StartType:   mgr.StartAutomatic,
		}, "run", "-config", cfgPath)
		if err != nil {
			return fmt.Errorf("не удалось создать службу: %w", err)
		}
		defer s.Close()
	} else {
		c, err := s.Config()
		if err != nil {
			return err
		}
		c.BinaryPathName = syscall.EscapeArg(exe) + " run -config " + syscall.EscapeArg(cfgPath)
		c.StartType = mgr.StartAutomatic
		if err := s.UpdateConfig(c); err != nil {
			return fmt.Errorf("не удалось обновить службу: %w", err)
		}
	}

	// Перезапуск при падении.
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
	}, 86400)

	return s.Start()
}

// Uninstall останавливает и удаляет службу.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return errors.New("служба ipblock не установлена")
	}
	defer s.Close()
	if err := stopAndWait(s); err != nil {
		return err
	}
	return s.Delete()
}

func Start() error {
	return withService(func(s *mgr.Service) error { return s.Start() })
}

func Stop() error {
	return withService(stopAndWait)
}

func withService(fn func(*mgr.Service) error) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return errors.New("служба ipblock не установлена (выполните ipblock install)")
	}
	defer s.Close()
	return fn(s)
}

func stopAndWait(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("не удалось остановить службу: %w", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		if st, err = s.Query(); err == nil && st.State == svc.Stopped {
			return nil
		}
	}
	return errors.New("служба не остановилась за 20 секунд")
}

// Run выполняет run как службу Windows либо, при запуске из консоли, до Ctrl+C.
func Run(run func(ctx context.Context) error) error {
	if Interactive() {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return run(ctx)
	}
	return svc.Run(Name, &handler{run: run})
}

type handler struct {
	run func(ctx context.Context) error
}

func (h *handler) Execute(_ []string, reqs <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case err := <-done:
			if err != nil {
				return false, 1
			}
			return false, 0
		case c := <-reqs:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		}
	}
}

const (
	runKey  = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	ownKey  = `SOFTWARE\ipblock`
	trayExe = "ipblock-tray.exe"
)

// TrayBinaryPath — куда install кладёт программу значка.
func TrayBinaryPath() string {
	return filepath.Join(filepath.Dir(BinaryPath()), trayExe)
}

// InstallTray ставит значок в автозапуск для всех пользователей и запускает его.
// Возвращает false, если программы значка рядом нет.
func InstallTray(cfgPath string) (bool, error) {
	src := traySource(trayExe)
	if src == "" {
		return false, nil
	}
	stopTray() // иначе файл занят и не перезапишется
	dst := TrayBinaryPath()
	if err := copyFile(src, dst); err != nil {
		return false, err
	}

	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE)
	if err != nil {
		return false, err
	}
	err = k.SetStringValue(Name, syscall.EscapeArg(dst)+" -config "+syscall.EscapeArg(cfgPath))
	k.Close()
	if err != nil {
		return false, err
	}
	// Значок, запущенный без аргументов, берёт путь к настройкам отсюда.
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, ownKey, registry.SET_VALUE); err == nil {
		_ = k.SetStringValue("ConfigPath", cfgPath)
		k.Close()
	}

	// Запуск через explorer: значок стартует с обычными правами пользователя,
	// а не с правами администратора, под которыми идёт установка.
	_ = exec.Command("explorer.exe", dst).Start()
	return true, nil
}

// UninstallTray закрывает значок и убирает его из автозапуска.
func UninstallTray() {
	stopTray()
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE); err == nil {
		_ = k.DeleteValue(Name)
		k.Close()
	}
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, ownKey)
}

func stopTray() {
	if exec.Command("taskkill", "/F", "/IM", trayExe).Run() == nil {
		time.Sleep(500 * time.Millisecond) // дать системе отпустить файл
	}
}
