package main

import (
	"fmt"
	"math/big"
	"math/rand"
	"strings"
)

var LENGTH int = 20

// PrivateKey private key
type PrivateKey struct {
	N uint64
	D uint64
}

// PublicKey private key
type PublicKey struct {
	N uint64
	E uint64
}

func Test() {
	bytes := make([]byte, LENGTH)
	publicKey, privateKey := generateKeyPair(2048)
	encrypted := Encode(bytes, &publicKey)
	_, error := Decode(encrypted, &privateKey)
	if error != nil {
		fmt.Println(error)
	}
}

func generateKeyPair(keySize uint64) (PublicKey, PrivateKey) {
	p := Sieve(keySize)
	q := Sieve(keySize)
	N := p * q
	var e uint64

	for {
		k := rand.Intn(int(keySize))
		if GCD(k, int((p-1)*(q-1))) == 1 {
			e = uint64(k)
			break
		}

	}

	d := new(big.Int).ModInverse(big.NewInt(int64(e)), big.NewInt((int64(p)-1)*(int64(q)-1)))
	D := d.Uint64()
	publicKey := PublicKey{
		N: N,
		E: e,
	}
	privateKey := PrivateKey{
		N: N,
		D: D,
	}

	return publicKey, privateKey
}

var split = "\xff\xfe\xff"

// Encode encode bytes
func Encode(bs []byte, pub *PublicKey) (be []byte) {
	e, n := pub.E, pub.N

	bet := make([]string, 0)
	for _, b := range bs {
		m := new(big.Int).SetBytes([]byte{b})
		c := new(big.Int).Exp(m, big.NewInt(int64(e)), big.NewInt(int64(n))) //  m ** e % n
		bet = append(bet, string(c.Bytes()))
	}
	return []byte(strings.Join(bet, split))
}

// Decode decode bytes
func Decode(be []byte, pri *PrivateKey) (bs []byte, err error) {
	d, n := pri.D, pri.N

	bs = make([]byte, 0)
	for _, b := range strings.Split(string(be), split) {
		c := new(big.Int).SetBytes([]byte(b))
		m := new(big.Int).Exp(c, big.NewInt(int64(d)), big.NewInt(int64(n))) //c ** d % n
		bs = append(bs, m.Bytes()[0])
	}

	return bs, nil
}
