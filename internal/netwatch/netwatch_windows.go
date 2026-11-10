// Package netwatch сообщает об изменениях сети: появился или исчез адрес,
// сменился шлюз по умолчанию. По такому сигналу сервис сразу закрывает доступ
// и только потом перепроверяет IP.
package netwatch

import (
	"context"

	"golang.org/x/sys/windows"
)

// Watch подписывается на изменения сети и шлёт сигнал в ch (без блокировки:
// если сигнал уже ждёт обработки, новый не нужен). Подписка снимается при отмене ctx.
func Watch(ctx context.Context, ch chan<- struct{}) error {
	notify := func() {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	structural := func(typ uint32) bool {
		return typ == windows.MibAddInstance || typ == windows.MibDeleteInstance
	}

	// Адрес появился или исчез на любом интерфейсе. Продление аренды DHCP сюда
	// не попадает: оно приходит как изменение параметров, а не как добавление.
	addrCb := windows.NewCallback(func(_ uintptr, _ *windows.MibUnicastIpAddressRow, typ uint32) uintptr {
		if structural(typ) {
			notify()
		}
		return 0
	})
	// Появился или исчез маршрут по умолчанию (сменился шлюз, включился VPN).
	// VPN часто не трогает 0.0.0.0/0, а добавляет две половины — 0.0.0.0/1 и 128.0.0.0/1.
	routeCb := windows.NewCallback(func(_ uintptr, row *windows.MibIpForwardRow2, typ uint32) uintptr {
		if row != nil && row.DestinationPrefix.PrefixLength <= 1 && structural(typ) {
			notify()
		}
		return 0
	})

	var hAddr, hRoute windows.Handle
	if err := windows.NotifyUnicastIpAddressChange(windows.AF_UNSPEC, addrCb, nil, false, &hAddr); err != nil {
		return err
	}
	if err := windows.NotifyRouteChange2(windows.AF_UNSPEC, routeCb, nil, false, &hRoute); err != nil {
		_ = windows.CancelMibChangeNotify2(hAddr)
		return err
	}
	go func() {
		<-ctx.Done()
		_ = windows.CancelMibChangeNotify2(hAddr)
		_ = windows.CancelMibChangeNotify2(hRoute)
	}()
	return nil
}
