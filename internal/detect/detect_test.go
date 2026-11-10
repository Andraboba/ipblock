package detect

import "testing"

func TestParseBody(t *testing.T) {
	ok := map[string]string{
		"203.0.113.7\n":       "203.0.113.7",
		"  2001:db8::1  ":     "2001:db8::1",
		"::ffff:198.51.100.4": "198.51.100.4",
		"fl=1f1\nh=example.com\nip=203.0.113.9\nts=1.5\nloc=NL\n": "203.0.113.9",
	}
	for body, want := range ok {
		got, err := ParseBody(body)
		if err != nil || got.String() != want {
			t.Errorf("ParseBody(%q) = %v, %v; ожидалось %s", body, got, err, want)
		}
	}
	for _, body := range []string{"", "<html>blocked</html>", "ip=не адрес", "203.0.113.7 extra"} {
		if _, err := ParseBody(body); err == nil {
			t.Errorf("ParseBody(%q) должен вернуть ошибку", body)
		}
	}
}

func TestHost(t *testing.T) {
	if Host("https://api.ipify.org") != "api.ipify.org" || Host("https://ifconfig.me/ip") != "ifconfig.me" || Host("мусор") != "мусор" {
		t.Error("Host разбирает адрес сервиса неверно")
	}
}
