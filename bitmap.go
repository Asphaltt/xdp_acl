package main

import (
	"fmt"
	"reflect"
	"strings"
	"unsafe"
)

const (
	bitmapSize = 64
	bitmapMask = bitmapSize - 1
)

type bitmap []uint64

func newBitmap(arrSize int) bitmap {
	return make(bitmap, arrSize)
}

func (b bitmap) Set(index uint32) {
	b[index>>6] |= 1 << (index & bitmapMask) // >>6 = /64, &63 = %64
}

func (b bitmap) MarshalBinary() ([]byte, error) {
	bm := (*reflect.SliceHeader)(unsafe.Pointer(&b))

	var bytes []byte
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&bytes))
	sh.Data = bm.Data
	sh.Len = len(b) << 3 // <<3 = *8
	sh.Cap = sh.Len
	return bytes, nil
}

func (b bitmap) String() string {
	var s []string
	for _, n := range b {
		s = append(s, fmt.Sprintf("%b", n))
	}
	return fmt.Sprintf("{%s}", strings.Join(s, " "))
}
