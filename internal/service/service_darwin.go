package service

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

const (
	label     = "com.ipblock.daemon"
	plistPath = "/Library/LaunchDaemons/" + label + ".plist"
)

// IsAdmin сообщает, запущена ли программа от root.
func IsAdmin() bool { return os.Geteuid() == 0 }

// Interactive — на macOS вывод в stdout безвреден и под launchd.
func Interactive() bool { return true }

// BinaryPath — куда install кладёт программу.
func BinaryPath() string { return "/usr/local/bin/ipblock" }

// Install кладёт программу в /usr/local/bin, создаёт LaunchDaemon и запускает его.
func Install(cfgPath string) error {
	_ = bootout() // если уже установлен — останавливаем перед заменой файла
	exe := BinaryPath()
	if err := copySelf(exe); err != nil {
		return err
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>` + label + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + esc(exe) + `</string>
		<string>run</string>
		<string>-config</string>
		<string>` + esc(cfgPath) + `</string>
	</array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>StandardErrorPath</key><string>/var/log/ipblock.err.log</string>
</dict>
</plist>
`
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		return err
	}
	return Start()
}

// Uninstall останавливает сервис и удаляет LaunchDaemon.
func Uninstall() error {
	_ = bootout()
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func Start() error {
	if _, err := os.Stat(plistPath); err != nil {
		return fmt.Errorf("сервис не установлен (выполните sudo ipblock install)")
	}
	return launchctl("bootstrap", "system", plistPath)
}

func Stop() error { return bootout() }

func bootout() error { return launchctl("bootout", "system/"+label) }

func launchctl(args ...string) error {
	out, err := exec.Command("launchctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func esc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// Run выполняет run до SIGINT/SIGTERM (launchd останавливает сервис через SIGTERM).
func Run(run func(ctx context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx)
}

const (
	trayLabel = "com.ipblock.tray"
	trayPlist = "/Library/LaunchAgents/" + trayLabel + ".plist"
	trayName  = "ipblock-tray"
)

// TrayBinaryPath — куда install кладёт программу значка.
func TrayBinaryPath() string { return "/usr/local/bin/" + trayName }

// InstallTray ставит значок в автозапуск (LaunchAgent для всех пользователей) и запускает его
// у того, кто сейчас работает за компьютером. Возвращает false, если программы значка рядом нет.
func InstallTray(cfgPath string) (bool, error) {
	src := traySource(trayName)
	if src == "" {
		return false, nil
	}
	gui := "gui/" + consoleUID()
	_ = launchctl("bootout", gui+"/"+trayLabel)
	dst := TrayBinaryPath()
	if err := copyFile(src, dst); err != nil {
		return false, err
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>` + trayLabel + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + esc(dst) + `</string>
		<string>-config</string>
		<string>` + esc(cfgPath) + `</string>
	</array>
	<key>RunAtLoad</key><true/>
	<key>LimitLoadToSessionType</key><string>Aqua</string>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key><false/>
	</dict>
</dict>
</plist>
`
	if err := os.WriteFile(trayPlist, []byte(plist), 0o644); err != nil {
		return false, err
	}
	// Если сейчас никто не вошёл в систему, значок появится при следующем входе.
	_ = launchctl("bootstrap", gui, trayPlist)
	return true, nil
}

// UninstallTray закрывает значок и убирает его из автозапуска.
func UninstallTray() {
	_ = launchctl("bootout", "gui/"+consoleUID()+"/"+trayLabel)
	_ = os.Remove(trayPlist)
}

// consoleUID — идентификатор пользователя, который сейчас работает за компьютером.
func consoleUID() string {
	if out, err := exec.Command("stat", "-f", "%u", "/dev/console").Output(); err == nil {
		if uid := strings.TrimSpace(string(out)); uid != "" && uid != "0" {
			return uid
		}
	}
	if uid := os.Getenv("SUDO_UID"); uid != "" {
		return uid
	}
	return "501"
}
