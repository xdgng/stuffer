package main

import "io"

type BitWriter struct {
	inner       io.Writer
	currentByte byte
	currentPos  int
}

func NewBitWriter(inner io.Writer) *BitWriter {
	return &BitWriter{
		inner:       inner,
		currentByte: 0,
		currentPos:  0,
	}
}

func (bw *BitWriter) WriteBit(bit bool) error {
	if bit {
		bw.currentByte |= (1 << bw.currentPos)
	}
	bw.currentPos++
	if bw.currentPos >= 8 {
		return bw.Flush()
	}
	return nil
}

func (bw *BitWriter) Flush() error {
	_, err := bw.inner.Write([]byte{bw.currentByte})
	bw.currentByte = 0
	bw.currentPos = 0
	return err
}
