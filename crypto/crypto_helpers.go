package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

//
// detShuffleBytes deterministically rearranges bytes from email+password using secret.
// Same (email,password,secret) => same output.
func detShuffleBytes(data []byte, secret []byte) []byte {
	seed := hmacSHA256(secret, data) // 32 bytes

	// Fisher–Yates on index array, using deterministic RNG from seed.
	idx := make([]int, len(data))
	for i := range idx {
		idx[i] = i
	}

	rng := newDetRNG(seed)
	for i := len(idx) - 1; i > 0; i-- {
		j := rng.intn(i + 1)
		idx[i], idx[j] = idx[j], idx[i]
	}

	out := make([]byte, len(data))
	for k := range idx {
		out[k] = data[idx[k]]
	}
	return out
}

func hmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

// detRNG: deterministic byte stream from SHA256(seed || counter_be).
// Not cryptographic PRNG; good enough for reproducible permutation.
type detRNG struct {
	seed    [32]byte
	counter uint64
	pool    []byte
}

func newDetRNG(seed []byte) *detRNG {
	var s [32]byte
	copy(s[:], seed)
	return &detRNG{seed: s}
}

func (r *detRNG) refill() {
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], r.counter)
	r.counter++

	h := sha256.New()
	h.Write(r.seed[:])
	h.Write(ctr[:])
	r.pool = h.Sum(nil) // 32 bytes
}

func (r *detRNG) byte() byte {
	if len(r.pool) == 0 {
		r.refill()
	}
	b := r.pool[0]
	r.pool = r.pool[1:]
	return b
}

func (r *detRNG) intn(n int) int {
	if n <= 0 {
		return 0
	}
	// rejection sampling to avoid modulo bias
	limit := byte(256 - (256 % n))
	for {
		x := r.byte()
		if x < limit {
			return int(x) % n
		}
	}
}
