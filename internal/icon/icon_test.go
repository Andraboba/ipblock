package icon

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"testing"
)

func TestPNGDecodes(t *testing.T) {
	for _, k := range []Kind{Open, Closed, Partial, Offline} {
		img, err := png.Decode(bytes.NewReader(PNG(k, 32)))
		if err != nil {
			t.Fatalf("kind %d: %v", k, err)
		}
		if img.Bounds().Dx() != 32 {
			t.Errorf("kind %d: ширина %d", k, img.Bounds().Dx())
		}
		// Центр закрашен, угол прозрачен.
		if _, _, _, a := img.At(16, 16).RGBA(); a == 0 {
			t.Errorf("kind %d: центр прозрачный", k)
		}
		if _, _, _, a := img.At(0, 0).RGBA(); a != 0 {
			t.Errorf("kind %d: угол непрозрачный", k)
		}
	}
}

func TestICOLayout(t *testing.T) {
	sizes := []int{16, 32, 48}
	data := ICO(Closed, sizes...)
	le := binary.LittleEndian
	if le.Uint16(data[0:]) != 0 || le.Uint16(data[2:]) != 1 || int(le.Uint16(data[4:])) != len(sizes) {
		t.Fatalf("неверный заголовок: % x", data[:6])
	}
	end := 6 + 16*len(sizes)
	for i, s := range sizes {
		e := data[6+16*i:]
		length, offset := int(le.Uint32(e[8:])), int(le.Uint32(e[12:]))
		if int(e[0]) != s || le.Uint16(e[6:]) != 32 || offset != end {
			t.Errorf("запись %d: размер %d, бит %d, смещение %d (ожидалось %d)", i, e[0], le.Uint16(e[6:]), offset, end)
		}
		want := 40 + s*s*4 + (s+31)/32*4*s
		if length != want {
			t.Errorf("запись %d: длина %d, ожидалось %d", i, length, want)
		}
		hdr := data[offset:]
		if le.Uint32(hdr[0:]) != 40 || int(le.Uint32(hdr[4:])) != s || int(le.Uint32(hdr[8:])) != 2*s {
			t.Errorf("запись %d: неверный заголовок DIB", i)
		}
		end += length
	}
	if end != len(data) {
		t.Errorf("длина файла %d, ожидалось %d", len(data), end)
	}
}
