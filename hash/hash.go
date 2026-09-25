package hash

import (
	"encoding/binary"
	"strconv"
	"strings"
)

func Murmur64aSum[T ~[]byte | string](data T) uint64 {
	b := []byte(data)

	const seed uint64 = 0
	const mix uint64 = 0xc6a4a7935bd1e995
	const shifts = 47

	var hash uint64 = seed ^ (uint64(len(b)) * mix)

	for len(b) >= 8 {
		key := binary.LittleEndian.Uint64(b)
		b = b[8:]

		key *= mix
		key ^= key >> shifts
		key *= mix

		hash ^= key
		hash *= mix
	}

	switch len(b) & 7 /* we know len(b) <= 7, but just so the compiler knows it can optimize this */ {
	case 7:
		hash ^= uint64(b[6]) << uint64(8*6)
		fallthrough
	case 6:
		hash ^= uint64(b[5]) << uint64(8*5)
		fallthrough
	case 5:
		hash ^= uint64(b[4]) << uint64(8*4)
		fallthrough
	case 4:
		hash ^= uint64(b[3]) << uint64(8*3)
		fallthrough
	case 3:
		hash ^= uint64(b[2]) << uint64(8*2)
		fallthrough
	case 2:
		hash ^= uint64(b[1]) << uint64(8*1)
		fallthrough
	case 1:
		hash ^= uint64(b[0])
		hash *= mix
	}

	// Equivalent to the above switch statement, but a decent bit slower.
	/*if len(b) > 0 {
		for i := len(b) - 1; i >= 0; i-- {
			hash ^= uint64(b[i]) << uint64(8*i)
		}
		hash *= mix
	}*/

	hash ^= hash >> shifts

	hash *= mix
	hash ^= hash >> shifts

	return hash
}

// Turns a 64-bit murmur hash into a thin 32-bit murmur hash.
func Thin(hash uint64) uint32 {
	return uint32(hash >> 32)
}

func DatalibHashSum[T ~[]byte | string](data T) uint32 {
	b := []byte(data)
	hash := uint32(5381)
	for _, c := range b {
		hash = hash*33 + uint32(c)
	}
	hash -= 5381
	return hash
}

// Parse64 parses a big endian 64-bit
// unsigned integer with optional 0x prefix.
func Parse64(s string) (uint64, error) {
	s = strings.TrimPrefix(s, "0x")
	x, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, err
	}
	return x, nil
}

// Parse32 parses a big endian 32-bit
// unsigned integer with optional 0x prefix.
func Parse32(s string) (uint32, error) {
	s = strings.TrimPrefix(s, "0x")
	x, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, err
	}
	return uint32(x), nil
}

func SplitMix64(x uint64) uint64 {
	z := uint64(x + 0x9e3779b97f4a7c15)
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}
