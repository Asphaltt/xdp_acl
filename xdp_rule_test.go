package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestActionKeyPriority(t *testing.T) {
	for _, n := range []uint32{
		0, 1, 2, 3, 4, 10, 100, 666, 2333,
	} {
		priority := uint32(n)
		key := getActionKey(priority)
		assert.Equal(t, uint64(priority), key.getPriority())
	}
}
