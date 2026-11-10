package procs

// Proc — запущенный процесс.
type Proc struct {
	PID  int
	PPID int
	Name string // имя исполняемого файла
	Path string // полный путь; пусто, если системе не хватило прав его узнать
}
