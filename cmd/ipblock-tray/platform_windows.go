package main

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"ipblock/internal/icon"
)

var icons = map[icon.Kind][]byte{}

func iconBytes(k icon.Kind) []byte {
	if icons[k] == nil {
		icons[k] = icon.ICO(k, 16, 20, 24, 32, 48)
	}
	return icons[k]
}

// singleInstance возвращает false, если значок уже запущен в этом сеансе пользователя.
func singleInstance() bool {
	name, _ := windows.UTF16PtrFromString(`Local\ipblock-tray`)
	_, err := windows.CreateMutex(nil, false, name)
	return err != windows.ERROR_ALREADY_EXISTS
}

// installedConfigPath — путь к настройкам, записанный командой `ipblock install`.
func installedConfigPath() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\ipblock`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, _ := k.GetStringValue("ConfigPath")
	return v
}

// openConfig открывает настройки в Блокноте с правами администратора:
// файл лежит в ProgramData и обычному пользователю на запись закрыт.
func openConfig(path string) { shellExecute("runas", path) }

func openLog(path string) { shellExecute("open", path) }

func shellExecute(verb, file string) {
	v, _ := windows.UTF16PtrFromString(verb)
	exe, _ := windows.UTF16PtrFromString("notepad.exe")
	arg, _ := windows.UTF16PtrFromString(`"` + file + `"`)
	_ = windows.ShellExecute(0, v, exe, arg, nil, windows.SW_SHOWNORMAL)
}

// Панель, запущенная из этого значка: её адрес и ссылка с ключом.
var panel struct {
	mu   sync.Mutex
	addr string
	url  string
}

// openPanel открывает панель управления в браузере.
//
// Самой панели нужны права администратора (сохранять настройки, видеть чужие
// процессы), поэтому Windows спросит разрешение на её запуск. Браузер же должен
// открыться с обычными правами пользователя — поэтому ссылку открывает значок,
// а не панель. Для этого значок сам выбирает панели порт и ключ.
func openPanel(cfgPath string) {
	panel.mu.Lock()
	defer panel.mu.Unlock()

	// Панель уже работает — просто показываем её ещё раз.
	if panel.addr != "" && reachable(panel.addr) {
		openInBrowser(panel.url)
		return
	}

	addr, err := freeAddr()
	if err != nil {
		return
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return
	}
	token := hex.EncodeToString(raw)
	url := "http://" + addr + "/?t=" + token

	verb, _ := windows.UTF16PtrFromString("runas")
	exe, _ := windows.UTF16PtrFromString(mainBinary("ipblock.exe"))
	args, _ := windows.UTF16PtrFromString(
		`ui -no-browser -listen ` + addr + ` -token ` + token + ` -config "` + cfgPath + `"`)
	if err := windows.ShellExecute(0, verb, exe, args, nil, windows.SW_SHOWMINNOACTIVE); err != nil {
		return // пользователь отказал в запросе прав
	}
	panel.addr, panel.url = addr, url

	// Ждём, пока панель начнёт отвечать (ответ на запрос прав может занять время).
	go func() {
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			if reachable(addr) {
				openInBrowser(url)
				return
			}
			time.Sleep(300 * time.Millisecond)
		}
	}()
}

// freeAddr подбирает свободный порт на этом компьютере.
func freeAddr() (string, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer ln.Close()
	return ln.Addr().String(), nil
}

func reachable(addr string) bool {
	c, err := net.DialTimeout("tcp4", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// openInBrowser открывает ссылку в браузере по умолчанию.
func openInBrowser(url string) {
	verb, _ := windows.UTF16PtrFromString("open")
	target, _ := windows.UTF16PtrFromString(url)
	_ = windows.ShellExecute(0, verb, target, nil, nil, windows.SW_SHOWNORMAL)
}
