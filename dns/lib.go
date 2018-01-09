package dns

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"math/rand"
	"strings"
	"sync"
	"time"
)

const (
	maxDominName   = 255
	maxCompression = 2 << 13
)

var (
	idLock  sync.Mutex
	idRand  *rand.Rand
	letters = []byte("1234567890abcdefghijklmnopqrstuvwxyz")
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// GenRandomType Most type of dns code less than 100
func GenRandomType() uint16 {
	return uint16(rand.Intn(10))
}

// GenRandomDomain will generate the random domain name with the fix length
// Argument : length is the length of sub domain name, domain is the tld name
// Return : random domain name
func GenRandomDomain(length int, domain string) string {
	if length == 0 {
		return domain
	}
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	if domain == "." {
		return string(b)
	}
	return string(b) + "." + domain
}

// GenerateRandomID will return a uint16 id
// Args: dynamic = true will return a new random id
// 	     dynamic = false will return uint16(0xfe)
// Return: id/uint16
func GenerateRandomID(dynamic bool) uint16 {
	if dynamic == false {
		return uint16(0xfffe)
	}
	idLock.Lock()
	if idRand == nil {
		var seed int64
		var buf [8]byte
		if _, err := crand.Read(buf[:]); err == nil {
			seed = int64(binary.LittleEndian.Uint16(buf[:]))
		} else {
			seed = rand.Int63()
		}
		idRand = rand.New(rand.NewSource(seed))
	}

	id := uint16(idRand.Uint32())
	idLock.Unlock()
	return id
}

// FqdnFormat function will check the domain name and return formated name
// Arguments : string
// Return    : string
func FqdnFormat(s string) string {
	l := len(s)
	if l == 0 {
		return "."
	}
	if s[l-1] != '.' {
		return s + "."
	}
	return s
}

// PackDomainName will return the []byte slice from the input domain name
// Arguments : string
// Return []byte
func PackDomainName(name string) []byte {
	var nameBuffer bytes.Buffer
	nameSplited := strings.Split(name, ".")
	for _, temp := range nameSplited {
		if temp == "" {
			nameBuffer.WriteByte(0)
		} else {
			nameBuffer.WriteByte(byte(len(temp)))
			nameBuffer.WriteString(temp)
		}
	}
	return nameBuffer.Bytes()
}

// ByteSliceCompare will compare the two slice and return true when equal.
// Arguments : []byte
// Return    : bool
func ByteSliceCompare(a, b []byte) bool {

	if a == nil && b == nil {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
