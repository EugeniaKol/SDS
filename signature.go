package main

import (
	"crypto/sha256"
)

type Signature struct {
	Hash      []byte
	PublicKey *PublicKey
}

func CreateSignature(msg []byte, pk PrivateKey, pub PublicKey) Signature {
	var sign Signature
	h := sha256.Sum256(msg)
	hash := h[:]
	//applying rsa with private key
	key := &PublicKey{
		N: pk.N,
		E: pk.D,
	}
	signature := Encode(hash, key)

	//storing hash and public key for checking
	sign.Hash = signature
	sign.PublicKey = &pub

	return sign
}

func VerifySignature(msg []byte, sign Signature) bool {
	h := sha256.Sum256(msg)
	hash := h[:]
	//applying rsa with public key
	key := &PrivateKey{
		N: sign.PublicKey.N,
		D: sign.PublicKey.E,
	}
	signatureHash, err := Decode(sign.Hash, key)
	if err != nil {
		return false
	}

	//checking if decrypted hash matches the hashed message
	for i, h := range hash {
		if h != signatureHash[i] {
			return false
		}
	}
	return true
}

func Usage() {
	publicKey, privateKey := generateKeyPair(20)
	msg := []byte("message for encryption")
	signature := CreateSignature(msg, privateKey, publicKey)
	VerifySignature(msg, signature)
}
