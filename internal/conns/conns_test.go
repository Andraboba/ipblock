package conns

import "testing"

func TestParseLsof(t *testing.T) {
	out := "p412\n" +
		"n192.168.1.5:54321->203.0.113.7:443\n" +
		"n*:8080\n" + // слушающий сокет
		"n127.0.0.1:50000->127.0.0.1:50001\n" + // обращение к себе
		"p977\n" +
		"n[2001:db8::5]:60000->[2001:db8:1::9]:993\n" +
		"n[::ffff:10.0.0.2]:60001->[::ffff:198.51.100.4]:25\n"
	got := ParseLsof(out)
	want := []struct {
		pid    int
		remote string
		local  uint16
	}{
		{412, "203.0.113.7:443", 54321},
		{977, "[2001:db8:1::9]:993", 60000},
		{977, "198.51.100.4:25", 60001},
	}
	if len(got) != len(want) {
		t.Fatalf("получено %d соединений: %+v", len(got), got)
	}
	for i, w := range want {
		if got[i].PID != w.pid || got[i].Remote.String() != w.remote || got[i].LocalPort != w.local {
			t.Errorf("[%d] получено %+v, ожидалось %+v", i, got[i], w)
		}
	}
}
