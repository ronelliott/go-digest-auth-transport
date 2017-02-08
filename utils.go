package dat

import (
	"fmt"
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().Unix())
}

// Generate random bytes
func RandBytes(count int) ([]byte, error) {
	out := make([]byte, count)
	_, err := rand.Read(out)

	if err != nil {
		return nil, err
	}

	return out, nil
}

// Generate a random hex string
func RandHexStr(count int) (string, error) {
	data, err := RandBytes(count)

	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", data), nil
}
