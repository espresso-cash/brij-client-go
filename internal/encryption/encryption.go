package encryption

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

func Encrypt(secretKey [32]byte, data []byte) (encrypted []byte, hash string, err error) {
	encrypted, err = encryptSecretBox(secretKey, data)
	if err != nil {
		return
	}

	hashBytes := sha256.Sum256(encrypted)
	hash = hex.EncodeToString(hashBytes[:])

	return
}

func DecryptUserData(secretKey [32]byte, data []byte) ([]byte, error) {
	decrypted, err := decryptSecretBox(secretKey, data)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

func DecodeSecretKey(encrypted string, user ed25519.PublicKey, privateKey ed25519.PrivateKey) ([32]byte, error) {
	var decryptedKey [32]byte

	sk := convertEd25519PrivateKeyToX25519(privateKey)
	pk, err := convertEd25519PublicKeyToX25519(user)
	if err != nil {
		return decryptedKey, err
	}

	decrypted, err := decryptSealedBox(sk, encrypted, pk)
	if err != nil {
		return decryptedKey, err
	}

	copy(decryptedKey[:], decrypted)

	return decryptedKey, nil
}

func decryptSecretBox(secretKey [32]byte, encryptedMessage []byte) ([]byte, error) {
	// Ensure the encrypted message is long enough to contain nonce
	if len(encryptedMessage) < 24 {
		return nil, errors.New("encrypted message too short")
	}

	// Extract the nonce from the encrypted message
	var nonce [24]byte
	copy(nonce[:], encryptedMessage[:24])

	// Decrypt the message using the secret key and nonce
	decrypted, ok := secretbox.Open(nil, encryptedMessage[24:], &nonce, &secretKey)
	if !ok {
		return nil, errors.New("decryption failed")
	}

	return decrypted, nil
}

func encryptSecretBox(secretKey [32]byte, message []byte) ([]byte, error) {
	// Generate a random nonce
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	// Encrypt the message using the secret key and nonce
	encrypted := secretbox.Seal(nonce[:], message, &nonce, &secretKey)

	return encrypted, nil
}

func SignMessage(privateKey ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(privateKey, message)
}

func decryptSealedBox(x25519PrivateKey [32]byte, encryptedMessage string, senderPublicKey [32]byte) ([]byte, error) {
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedMessage)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	copy(nonce[:], encryptedBytes[:24])

	decrypted, ok := box.Open(nil, encryptedBytes[24:], &nonce, &senderPublicKey, &x25519PrivateKey)
	if !ok {
		return nil, errors.New("decryption failed")
	}

	return decrypted, nil
}

func convertEd25519PublicKeyToX25519(ed25519PublicKey ed25519.PublicKey) ([32]byte, error) {
	p, err := new(edwards25519.Point).SetBytes(ed25519PublicKey)

	if err != nil {
		return [32]byte{}, err
	}

	return [32]byte(p.BytesMontgomery()), nil
}

func convertEd25519PrivateKeyToX25519(ed25519PrivateKey ed25519.PrivateKey) [32]byte {
	h := sha512.New()
	h.Write(ed25519PrivateKey.Seed())
	var x25519PrivateKey [32]byte
	copy(x25519PrivateKey[:], h.Sum(nil)[:32])
	x25519PrivateKey[0] &= 248
	x25519PrivateKey[31] &= 127
	x25519PrivateKey[31] |= 64
	return x25519PrivateKey
}
