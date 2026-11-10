// ipblock открывает доступ к заданным сайтам, IP-адресам и программам
// только тогда, когда компьютер выходит в сеть с разрешённого IP.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"time"

	"ipblock/internal/config"
	"ipblock/internal/engine"
	"ipblock/internal/firewall"
	"ipblock/internal/service"
	"ipblock/internal/ui"
)

var version = "0.1.0"

const usage = `ipblock — доступ к сайтам, адресам и программам только с разрешённых IP.

Использование: ipblock <команда> [-config путь]

  init        создать пример файла настроек
  check       показать текущие IP и решение по каждому правилу (ничего не меняет)
  selftest    проверить на этой машине, что блокировка действительно работает
  run         запустить в этом окне (нужны права администратора), Ctrl+C — выход
  install     установить сервис и значок с автозапуском и запустить их
  uninstall   удалить сервис и значок, снять все блокировки
  start/stop  запустить / остановить установленный сервис
  status      показать результат последней проверки сервиса
  ui          открыть панель управления в браузере (найти адреса программы, добавить в правило)
  clear       снять все блокировки (hosts и файрвол)
  version     показать версию

Файл настроек по умолчанию: %s
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, config.DefaultPath())
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath(), "путь к файлу настроек")
	noBrowser := fs.Bool("no-browser", false, "для ui: не открывать браузер, только напечатать ссылку")
	listen := fs.String("listen", "", "для ui: адрес панели вида 127.0.0.1:порт (по умолчанию порт выбирается сам)")
	token := fs.String("token", "", "для ui: ключ панели (по умолчанию случайный)")
	_ = fs.Parse(os.Args[2:])
	if abs, err := filepath.Abs(*cfgPath); err == nil {
		*cfgPath = abs
	}

	var err error
	switch cmd {
	case "init":
		err = cmdInit(*cfgPath)
	case "check":
		err = cmdCheck(*cfgPath)
	case "run":
		err = cmdRun(*cfgPath)
	case "install":
		err = cmdInstall(*cfgPath)
	case "selftest":
		if err = needAdmin(); err == nil {
			fmt.Println("Самопроверка (рабочие правила не затрагиваются):")
			if engine.SelfTest(os.Stdout) {
				fmt.Println("Всё работает: файрвол закрывает соединения, привязка к локальному адресу действует.")
				if len(firewall.Health()) > 0 {
					fmt.Println("Строки с [ !! ] — настройки системы, из-за которых защита действует не во всех сетях.")
					if runtime.GOOS == "windows" {
						fmt.Println("Включить брандмауэр для всех профилей: netsh advfirewall set allprofiles state on")
					}
				}
			} else {
				err = errors.New("самопроверка не пройдена — на этой машине блокировка работает не полностью")
			}
		}
	case "uninstall":
		if err = needAdmin(); err == nil {
			service.UninstallTray()
			if err = service.Uninstall(); err == nil {
				err = engine.ClearAll()
			}
			if err == nil {
				fmt.Println("Сервис и значок удалены, блокировки сняты.")
			}
		}
	case "start":
		if err = needAdmin(); err == nil {
			if err = service.Start(); err == nil {
				fmt.Println("Сервис запущен.")
			}
		}
	case "stop":
		if err = needAdmin(); err == nil {
			if err = service.Stop(); err == nil {
				fmt.Println("Сервис остановлен. При on_stop: lock доступ остался закрытым полностью — снять блокировки: ipblock clear")
			}
		}
	case "ui":
		if !service.IsAdmin() {
			fmt.Println("Панель запущена без прав администратора: смотреть можно, сохранять в настройки — нет.")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		err = ui.Run(ctx, ui.Options{ConfigPath: *cfgPath, OpenBrowser: !*noBrowser, Out: os.Stdout, Listen: *listen, Token: *token})
		stop()
	case "status":
		err = cmdStatus(*cfgPath)
	case "clear":
		if err = needAdmin(); err == nil {
			if err = engine.ClearAll(); err == nil {
				fmt.Println("Блокировки сняты. Работающий сервис поставит их снова при следующей проверке.")
			}
		}
	case "version":
		fmt.Printf("ipblock %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	case "help", "-h", "--help":
		fmt.Printf(usage, config.DefaultPath())
	default:
		fmt.Fprintf(os.Stderr, "неизвестная команда %q\n\n", cmd)
		fmt.Fprintf(os.Stderr, usage, config.DefaultPath())
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		os.Exit(1)
	}
}

func needAdmin() error {
	if service.IsAdmin() {
		return nil
	}
	if runtime.GOOS == "windows" {
		return errors.New("нужны права администратора: откройте терминал «от имени администратора»")
	}
	return errors.New("нужны права root: запустите команду через sudo")
}

func cmdInit(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("файл %s уже существует", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, config.Example, 0o644); err != nil {
		return err
	}
	if runtime.GOOS == "darwin" {
		// Группа admin (80) может править настройки в обычном редакторе, без sudo.
		_ = os.Chown(path, 0, 80)
		_ = os.Chmod(path, 0o664)
	}
	fmt.Printf("Создан пример настроек: %s\nОтредактируйте его и проверьте командой: ipblock check\n", path)
	return nil
}

func cmdCheck(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	snap := engine.Evaluate(ctx, cfg)
	snap.Warnings = firewall.Health()
	fmt.Print(snap)
	return nil
}

func cmdStatus(path string) error {
	data, err := os.ReadFile(engine.StatusPath(path))
	if err != nil {
		return fmt.Errorf("сервис ещё не делал проверок (нет %s)", engine.StatusPath(path))
	}
	var snap engine.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	fmt.Print(snap)
	if age := time.Since(snap.Time); age > 5*time.Minute {
		fmt.Printf("\nВнимание: последняя проверка была %s назад — похоже, сервис не работает.\n", age.Round(time.Minute))
	}
	return nil
}

func cmdRun(path string) error {
	if err := needAdmin(); err != nil {
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}

	var out io.Writer = io.Discard
	if service.Interactive() {
		out = os.Stdout
	}
	// Журнал не растёт бесконечно: при запуске файл больше 5 МБ начинается заново.
	if fi, err := os.Stat(cfg.LogFile); err == nil && fi.Size() > 5<<20 {
		_ = os.Remove(cfg.LogFile)
	}
	if f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		defer f.Close()
		out = io.MultiWriter(f, out)
	}
	logger := log.New(out, "", log.LstdFlags)

	return service.Run(engine.New(path, cfg, logger).Run)
}

func cmdInstall(path string) error {
	if err := needAdmin(); err != nil {
		return err
	}
	if _, err := config.Load(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("нет файла настроек %s — создайте его: ipblock init", path)
		}
		return err
	}
	if err := service.Install(path); err != nil {
		return err
	}
	fmt.Printf("Сервис установлен и запущен.\n  программа: %s\n  настройки: %s\n", service.BinaryPath(), path)
	switch ok, err := service.InstallTray(path); {
	case err != nil:
		fmt.Println("Значок установить не удалось:", err)
	case ok:
		fmt.Println("Значок добавлен в автозапуск и запущен.")
	default:
		fmt.Println("Значок не установлен: рядом с программой нет ipblock-tray (см. README, раздел «Сборка»).")
	}
	fmt.Println("Состояние: ipblock status")
	return nil
}
