package main

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"io"
	"os"
)

type WritableImage interface {
	image.Image
	Set(x, y int, c color.Color)
}

// embed a bit into a byte (set last bit to the value)
func bitEmbed(b byte, bit bool) byte {
	if bit {
		return b | 1
	} else {
		return b & (^byte(1))
	}
}

func colorToRGBA(col color.Color) color.RGBA {

	switch c := col.(type) {
	case color.RGBA:
		return c
	case color.NRGBA:
		return color.RGBA{
			R: c.R,
			G: c.G,
			B: c.B,
			A: c.A,
		}
	default:
		panic("unsupported color scheme")
	}
}

func colorEmbed(col color.Color, pos int, bit bool) color.Color {
	switch c := col.(type) {
	case color.RGBA:
		newc := color.RGBA{
			R: c.R,
			G: c.G,
			B: c.B,
			A: c.A,
		}
		switch pos {
		case 0:
			newc.R = bitEmbed(c.R, bit)
		case 1:
			newc.G = bitEmbed(c.G, bit)
		case 2:
			newc.B = bitEmbed(c.B, bit)
		default:
			fmt.Fprintf(os.Stderr, "Invalid color pos: %d, valid 0-2\n", pos)
		}
		return newc
	case color.NRGBA:
		newc := color.NRGBA{
			R: c.R,
			G: c.G,
			B: c.B,
			A: c.A,
		}
		switch pos {
		case 0:
			newc.R = bitEmbed(c.R, bit)
		case 1:
			newc.G = bitEmbed(c.G, bit)
		case 2:
			newc.B = bitEmbed(c.B, bit)
		default:
			fmt.Fprintf(os.Stderr, "Invalid color pos: %d, valid 0-2\n", pos)
		}
		return newc

	default:
		panic("unsupported color scheme")
	}
}

// last 260 bytes reserved for length and
type ImageByteWriter struct {
	im          WritableImage
	currentX    int
	currentY    int
	currentRGB  int
	currentByte int
	w           int
	h           int
	capacity    int
}

func NewImageByteWriter(im WritableImage) (*ImageByteWriter, error) {
	colorModel := im.ColorModel()
	if colorModel != color.RGBAModel && colorModel != color.NRGBAModel {
		return nil, fmt.Errorf("expected a RGB image")
	}
	ibw := &ImageByteWriter{
		im:          im,
		currentX:    0,
		currentY:    0,
		currentRGB:  0,
		currentByte: 0,
		w:           im.Bounds().Dx(),
		h:           im.Bounds().Dy(),
	}
	ibw.capacity = ibw.w * ibw.h * 3 / 8
	return ibw, nil
}

func (ibw *ImageByteWriter) increment() bool {
	if ibw.currentY >= ibw.h {
		return true
	}
	ibw.currentRGB++
	if ibw.currentRGB > 2 {
		ibw.currentRGB = 0
		ibw.currentX++
		if ibw.currentX >= ibw.w {
			ibw.currentX = 0
			ibw.currentY++
		}
	}
	return false
}

func (ibw *ImageByteWriter) writeByte(data byte) error {
	if ibw.capacity <= ibw.currentByte {
		return io.ErrUnexpectedEOF
	}
	for i := 0; i < 8; i++ {
		bit := (data & (1 << i)) != 0
		c := ibw.im.At(ibw.currentX, ibw.currentY)
		ibw.im.Set(ibw.currentX, ibw.currentY, colorEmbed(c, ibw.currentRGB, bit))
		if ibw.increment() {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

func (ibw *ImageByteWriter) Write(data []byte) (int, error) {
	var err error = nil
	if ibw.capacity-ibw.currentByte < len(data) {
		err = io.EOF
		data = data[:(ibw.capacity - ibw.currentByte)]
	}
	for i, b := range data {
		if e2 := ibw.writeByte(b); e2 != nil {
			return i, e2
		}
		ibw.currentByte++
	}
	return len(data), err
}

// finalpos = ((y * w) + x) * 3 + rgb
func (ibw *ImageByteWriter) setBitPos(bitpos int) error {
	if bitpos < 0 {
		bitpos = 0
	}
	ibw.currentRGB = bitpos % 3
	bitpos /= 3
	ibw.currentX = bitpos % ibw.w
	bitpos /= ibw.w
	ibw.currentY = bitpos
	if bitpos >= ibw.h {
		ibw.currentY = ibw.h
		ibw.currentX = 0
		ibw.currentRGB = 0
		return io.EOF
	}
	return nil
}

func (ibw *ImageByteWriter) BitPos() int {
	return (ibw.currentY*ibw.w+ibw.currentX)*3 + ibw.currentRGB
}

func (ibw *ImageByteWriter) Seek(offset int64, whence int) (int64, error) {
	var currentPos int64
	switch whence {
	case io.SeekCurrent:
		currentPos = int64(ibw.BitPos()) / 8
	case io.SeekStart:
		currentPos = 0
	case io.SeekEnd:
		currentPos = int64(ibw.capacity)
	default:
		return -1, fmt.Errorf("unknown seek whence")
	}
	currentPos += offset
	err := ibw.setBitPos(int(currentPos) * 8)
	return int64(ibw.BitPos() / 8), err
}

func (ibw *ImageByteWriter) Image() WritableImage {
	return ibw.im
}

func GetHiddenBytesFromImage(im image.Image) ([]byte, error) {
	colorModel := im.ColorModel()
	if colorModel != color.RGBAModel && colorModel != color.NRGBAModel {
		return nil, fmt.Errorf("expected a RGBA image")
	}
	var br bytes.Buffer
	bw := NewBitWriter(&br)
	w := im.Bounds().Dx()
	h := im.Bounds().Dy()
	for j := 0; j < h; j++ {
		for i := 0; i < w; i++ {
			c := colorToRGBA(im.At(i, j))
			if err := bw.WriteBit((c.R & 1) != 0); err != nil {
				return nil, err
			}
			if err := bw.WriteBit((c.G & 1) != 0); err != nil {
				return nil, err
			}
			if err := bw.WriteBit((c.B & 1) != 0); err != nil {
				return nil, err
			}
		}
	}
	return br.Bytes(), nil
}

func (ibw *ImageByteWriter) Capacity() int {
	return ibw.capacity
}
