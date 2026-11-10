// Package icon рисует значки состояния для области уведомлений.
// Картинки создаются программно, чтобы не хранить в проекте бинарные файлы.
package icon

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

// Kind — состояние, которое показывает значок.
type Kind int

const (
	Open    Kind = iota // доступ открыт: зелёный круг с галочкой
	Closed              // доступ закрыт: красный круг с полосой
	Partial             // часть правил закрыта или есть предупреждение: оранжевый круг с «!»
	Offline             // сервис не работает: серый круг с многоточием
)

var colors = map[Kind]color.NRGBA{
	Open:    {0x2E, 0xA0, 0x43, 0xFF},
	Closed:  {0xD1, 0x24, 0x2F, 0xFF},
	Partial: {0xD4, 0x86, 0x0B, 0xFF},
	Offline: {0x8B, 0x94, 0x9E, 0xFF},
}

// Draw рисует значок size×size пикселей со сглаживанием.
func Draw(k Kind, size int) *image.NRGBA {
	const ss = 4 // подвыборок на пиксель по каждой оси
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	base := colors[k]
	for y := range size {
		for x := range size {
			var disc, glyph int
			for sy := range ss {
				for sx := range ss {
					// Координаты подвыборки в квадрате [-1, 1], ось Y вниз.
					u := (float64(x)+(float64(sx)+0.5)/ss)/float64(size)*2 - 1
					v := (float64(y)+(float64(sy)+0.5)/ss)/float64(size)*2 - 1
					if math.Hypot(u, v) > 0.94 {
						continue
					}
					disc++
					if inGlyph(k, u, v) {
						glyph++
					}
				}
			}
			if disc == 0 {
				continue
			}
			// Цвет — смесь основы и белого знака; прозрачность — доля круга в пикселе.
			t := float64(glyph) / float64(disc)
			mix := func(c uint8) uint8 { return uint8(float64(c)*(1-t) + 255*t + 0.5) }
			img.SetNRGBA(x, y, color.NRGBA{mix(base.R), mix(base.G), mix(base.B), uint8(disc * 255 / (ss * ss))})
		}
	}
	return img
}

func inGlyph(k Kind, u, v float64) bool {
	switch k {
	case Open:
		return segDist(u, v, -0.46, 0.04, -0.14, 0.36) < 0.115 || segDist(u, v, -0.14, 0.36, 0.48, -0.30) < 0.115
	case Closed:
		return math.Abs(v) < 0.15 && math.Abs(u) < 0.54
	case Partial:
		return (math.Abs(u) < 0.12 && v > -0.56 && v < 0.14) || math.Hypot(u, v-0.44) < 0.14
	default:
		return math.Hypot(u+0.40, v) < 0.12 || math.Hypot(u, v) < 0.12 || math.Hypot(u-0.40, v) < 0.12
	}
}

// segDist — расстояние от точки (px, py) до отрезка (ax, ay)–(bx, by).
func segDist(px, py, ax, ay, bx, by float64) float64 {
	dx, dy := bx-ax, by-ay
	t := ((px-ax)*dx + (py-ay)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(px-(ax+t*dx), py-(ay+t*dy))
}

// PNG возвращает значок в формате PNG (для macOS).
func PNG(k Kind, size int) []byte {
	var buf bytes.Buffer
	_ = png.Encode(&buf, Draw(k, size))
	return buf.Bytes()
}

// ICO возвращает значок в формате .ico с несколькими размерами (для Windows).
// Каждая картинка — несжатый 32-битный DIB: этот вариант понимают все версии Windows.
func ICO(k Kind, sizes ...int) []byte {
	type entry struct {
		size int
		data []byte
	}
	var entries []entry
	for _, s := range sizes {
		entries = append(entries, entry{s, dib(Draw(k, s))})
	}

	var buf bytes.Buffer
	le := binary.LittleEndian
	w := func(v any) { _ = binary.Write(&buf, le, v) }
	w(uint16(0)) // зарезервировано
	w(uint16(1)) // тип: значок
	w(uint16(len(entries)))
	offset := 6 + 16*len(entries)
	for _, e := range entries {
		w(uint8(e.size)) // ширина
		w(uint8(e.size)) // высота
		w(uint8(0))      // цветов в палитре
		w(uint8(0))      // зарезервировано
		w(uint16(1))     // плоскостей
		w(uint16(32))    // бит на пиксель
		w(uint32(len(e.data)))
		w(uint32(offset))
		offset += len(e.data)
	}
	for _, e := range entries {
		buf.Write(e.data)
	}
	return buf.Bytes()
}

// dib кодирует картинку как BITMAPINFOHEADER + пиксели BGRA снизу вверх + пустую AND-маску.
func dib(img *image.NRGBA) []byte {
	size := img.Bounds().Dx()
	maskRow := (size + 31) / 32 * 4
	var buf bytes.Buffer
	le := binary.LittleEndian
	w := func(v any) { _ = binary.Write(&buf, le, v) }
	w(uint32(40))      // размер заголовка
	w(int32(size))     // ширина
	w(int32(size * 2)) // высота: картинка + маска
	w(uint16(1))       // плоскостей
	w(uint16(32))      // бит на пиксель
	w(uint32(0))       // без сжатия
	w(uint32(size * size * 4))
	w(int32(0))
	w(int32(0))
	w(uint32(0))
	w(uint32(0))
	for y := size - 1; y >= 0; y-- {
		for x := range size {
			c := img.NRGBAAt(x, y)
			buf.Write([]byte{c.B, c.G, c.R, c.A})
		}
	}
	buf.Write(make([]byte, maskRow*size))
	return buf.Bytes()
}
