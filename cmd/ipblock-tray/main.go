//go:build windows || (darwin && cgo)

// ipblock-tray — значок ipblock в области уведомлений (Windows) или в строке меню (macOS).
// Сам ничего не блокирует: показывает то, что решил сервис, читая его файл состояния.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"fyne.io/systray"

	"ipblock/internal/config"
	"ipblock/internal/engine"
	"ipblock/internal/icon"
)

const (
	maxRules = 12
	maxWarns = 3
	poll     = 2 * time.Second
)

func main() {
	cfgFlag := flag.String("config", "", "путь к файлу настроек сервиса")
	flag.Parse()
	cfgPath := *cfgFlag
	if cfgPath == "" {
		cfgPath = installedConfigPath()
	}
	if cfgPath == "" {
		cfgPath = config.DefaultPath()
	}
	if !singleInstance() {
		return
	}
	systray.Run(func() { onReady(cfgPath) }, func() {})
}

// view — всё, что показывает значок и его меню.
type view struct {
	kind    icon.Kind
	tooltip string
	head    string
	ip      string
	rules   []string
	warns   []string
}

func load(cfgPath string) view {
	offline := view{kind: icon.Offline, tooltip: "ipblock: сервис не работает", head: "Сервис ipblock не работает"}
	data, err := os.ReadFile(engine.StatusPath(cfgPath))
	if err != nil {
		return offline
	}
	var snap engine.Snapshot
	if json.Unmarshal(data, &snap) != nil {
		return offline
	}
	// Сервис переписывает файл при каждой проверке. Давно не обновлялся — сервис не работает.
	if time.Since(snap.Time) > 2*time.Duration(snap.IntervalSec)*time.Second+30*time.Second {
		offline.ip = "Последняя проверка: " + snap.Time.Format("02.01 15:04")
		return offline
	}

	v := view{}
	open := 0
	for _, r := range snap.Rules {
		line := "✕  " + r.Name + " — закрыто"
		if r.Allowed {
			open++
			line = "✓  " + r.Name + " — открыто"
		}
		v.rules = append(v.rules, line)
	}
	for _, w := range snap.Warnings {
		v.warns = append(v.warns, "⚠  "+shorten(w, 110))
	}
	switch {
	case snap.PublicAddrs() != "":
		v.ip = "Внешний IP: " + snap.PublicAddrs()
	case snap.PublicErr != "":
		v.ip = "Внешний IP не определяется"
	default:
		v.ip = "Проверка по локальным адресам"
	}

	total := len(snap.Rules)
	switch {
	case open == total:
		v.kind, v.head = icon.Open, "Доступ открыт"
	case open == 0:
		v.kind, v.head = icon.Closed, "Доступ закрыт"
	default:
		v.kind, v.head = icon.Partial, fmt.Sprintf("Открыто %d из %d", open, total)
	}
	if len(v.warns) > 0 {
		v.kind, v.head = icon.Partial, "Есть проблема — см. ниже"
	}
	v.tooltip = "ipblock: " + v.head
	return v
}

func onReady(cfgPath string) {
	mHead := systray.AddMenuItem("ipblock", "")
	mIP := systray.AddMenuItem("", "")
	mIP.Hide()
	systray.AddSeparator()
	var mWarns, mRules []*systray.MenuItem
	for range maxWarns {
		m := systray.AddMenuItem("", "")
		m.Hide()
		mWarns = append(mWarns, m)
	}
	for range maxRules {
		m := systray.AddMenuItem("", "")
		m.Hide()
		mRules = append(mRules, m)
	}
	systray.AddSeparator()
	mPanel := systray.AddMenuItem("Панель управления…", "Правила и поиск адресов программы")
	mCfg := systray.AddMenuItem("Файл настроек…", "Открыть файл настроек в редакторе")
	mLog := systray.AddMenuItem("Журнал", "Открыть журнал сервиса")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Убрать значок", "Сервис продолжит работать")

	// Пункт меню обновляем, только если текст изменился.
	shown := map[*systray.MenuItem]string{}
	set := func(m *systray.MenuItem, text string) {
		if shown[m] == text {
			return
		}
		shown[m] = text
		if text == "" {
			m.Hide()
			return
		}
		m.SetTitle(text)
		m.Show()
	}
	fill := func(items []*systray.MenuItem, lines []string) {
		for i, m := range items {
			if i < len(lines) {
				set(m, lines[i])
			} else {
				set(m, "")
			}
		}
	}

	lastKind := icon.Kind(-1)
	lastTip := ""
	refresh := func() {
		v := load(cfgPath)
		if v.kind != lastKind {
			lastKind = v.kind
			systray.SetIcon(iconBytes(v.kind))
		}
		if v.tooltip != lastTip {
			lastTip = v.tooltip
			systray.SetTooltip(v.tooltip)
		}
		set(mHead, v.head)
		set(mIP, v.ip)
		fill(mWarns, v.warns)
		fill(mRules, v.rules)
	}
	refresh()

	go func() {
		t := time.NewTicker(poll)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				refresh()
			case <-mPanel.ClickedCh:
				openPanel(cfgPath)
			case <-mCfg.ClickedCh:
				openConfig(cfgPath)
			case <-mLog.ClickedCh:
				openLog(logPath(cfgPath))
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

func logPath(cfgPath string) string {
	if cfg, err := config.Load(cfgPath); err == nil {
		return cfg.LogFile
	}
	return filepath.Join(filepath.Dir(cfgPath), "ipblock.log")
}

func shorten(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// mainBinary — программа ipblock, лежащая рядом со значком.
func mainBinary(name string) string {
	exe, err := os.Executable()
	if err != nil {
		return name
	}
	return filepath.Join(filepath.Dir(exe), name)
}
