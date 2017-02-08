package dat

import "sync"

// Counts usages for nonces
type NonceCountMap struct {
	// The counts for this map
	Counts map[string]int

	// The mutex for this map
	Mutex *sync.Mutex
}

var GlobalNonceCountMap *NonceCountMap

func init() {
	GlobalNonceCountMap = NewNonceCountMap()
}

// Create a new NonceCountMap
func NewNonceCountMap() *NonceCountMap {
	return &NonceCountMap{
		Counts: map[string]int{},
		Mutex:  &sync.Mutex{},
	}
}

// Add the count for the given nonce
func (counts *NonceCountMap) Add(nonce string, count int) {
	counts.Mutex.Lock()
	defer counts.Mutex.Unlock()
	counts.Counts[nonce] += count
}

// Increment the count for the given nonce
func (counts *NonceCountMap) Increment(nonce string) {
	counts.Add(nonce, 1)
}

// Get the count for the given nonce
func (counts *NonceCountMap) Count(nonce string) int {
	counts.Mutex.Lock()
	defer counts.Mutex.Unlock()
	return counts.Counts[nonce]
}

// Add the count for the given nonce
func NoncesAdd(nonce string, count int) {
	GlobalNonceCountMap.Add(nonce, count)
}

// Increment the count for the given nonce
func NoncesIncrement(nonce string) {
	GlobalNonceCountMap.Increment(nonce)
}

// Get the count for the given nonce
func NoncesCount(nonce string) int {
	return GlobalNonceCountMap.Count(nonce)
}
