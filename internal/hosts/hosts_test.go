package hosts

import (
	"strings"
	"testing"
)

func TestRenderAddUpdateRemove(t *testing.T) {
	orig := "127.0.0.1 localhost\n# мой комментарий\n10.0.0.5 nas\n"

	with := string(Render([]byte(orig), []string{"mail.example.com", "a.example.com", "mail.example.com"}))
	if !strings.HasPrefix(with, orig) {
		t.Fatalf("исходные строки потеряны:\n%s", with)
	}
	for _, want := range []string{"0.0.0.0 mail.example.com\n", ":: a.example.com\n", beginMarker, endMarker} {
		if !strings.Contains(with, want) {
			t.Errorf("нет %q в:\n%s", want, with)
		}
	}
	if strings.Count(with, "0.0.0.0 mail.example.com") != 1 {
		t.Errorf("дубликат домена:\n%s", with)
	}

	// Повторное применение ничего не меняет.
	if again := string(Render([]byte(with), []string{"a.example.com", "mail.example.com"})); again != with {
		t.Errorf("Render не идемпотентен:\n%s\n---\n%s", with, again)
	}

	// Замена набора.
	changed := string(Render([]byte(with), []string{"b.example.com"}))
	if strings.Contains(changed, "mail.example.com") || !strings.Contains(changed, "0.0.0.0 b.example.com") {
		t.Errorf("блок не заменён:\n%s", changed)
	}

	// Снятие блокировки возвращает исходный файл.
	if cleared := string(Render([]byte(with), nil)); cleared != orig {
		t.Errorf("после очистки:\n%q\nожидалось:\n%q", cleared, orig)
	}
}

func TestRenderKeepsCRLF(t *testing.T) {
	orig := "127.0.0.1 localhost\r\n"
	out := string(Render([]byte(orig), []string{"x.example.com"}))
	if strings.Contains(strings.ReplaceAll(out, "\r\n", ""), "\n") {
		t.Errorf("смешанные переводы строк: %q", out)
	}
	if back := string(Render([]byte(out), nil)); back != orig {
		t.Errorf("got %q, want %q", back, orig)
	}
}

func TestRenderMissingEndMarker(t *testing.T) {
	broken := "127.0.0.1 localhost\n" + beginLine + "\n0.0.0.0 x.example.com\n10.0.0.5 nas\n"
	out := string(Render([]byte(broken), nil))
	if out != "127.0.0.1 localhost\n10.0.0.5 nas\n" {
		t.Errorf("чужая строка после повреждённого блока потеряна: %q", out)
	}
}
