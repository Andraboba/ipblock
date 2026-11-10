package conns

import (
	"os/exec"
)

// Snapshot возвращает текущие TCP-соединения процессов, видимых пользователю,
// от имени которого запущена программа (для чужих процессов нужен sudo).
func Snapshot() ([]Conn, error) {
	out, err := exec.Command("lsof", "-nP", "-iTCP", "-F", "pn").Output()
	if err != nil && len(out) == 0 {
		return nil, err // lsof возвращает ошибку и при пустом списке — тогда вывода нет
	}
	return ParseLsof(string(out)), nil
}
