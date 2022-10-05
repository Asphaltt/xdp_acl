package main

import (
	"reflect"
	"unsafe"
)

const (
	bitmapArraySize = 160
	bitmapSize      = 64
	bitmapMask      = bitmapSize - 1
)

type bitmap [bitmapArraySize]uint64

func (b *bitmap) Set(index uint32) {
	(*b)[index>>6] |= 1 << (index & bitmapMask) // >>6 = /64, &63 = %64
}

func (b *bitmap) Reset(index uint32) {
	(*b)[index>>6] &= ^(1 << (index & bitmapMask)) // >>6 = /64, &63 = %64
}

func (b *bitmap) Get(index uint32) uint8 {
	return uint8(((*b)[index>>6] >> (index & bitmapMask)) & 0x1)
}

func (b bitmap) MarshalBinary() ([]byte, error) {
	var bytes []byte
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&bytes))
	sh.Data = uintptr(unsafe.Pointer(&b))
	sh.Len = bitmapArraySize << 3 // <<3 = *8
	sh.Cap = sh.Len
	return bytes, nil
}
