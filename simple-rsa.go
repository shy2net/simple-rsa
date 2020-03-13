package simplersa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io/ioutil"
)

// Hashes a message with RSA, sha256 is used for the hash algorithm with simple-rsa
func generateHash(message []byte) [32]byte {
	return sha256.Sum256(message)
}

// Sign Signs the message with provided private key
func Sign(message []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hashed := generateHash(message)
	return rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, hashed[:])
}

// SignFile Sign the provided file with the private key and return the stamp bytes
func SignFile(path string, privateKey *rsa.PrivateKey) ([]byte, error) {
	data, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	return Sign(data, privateKey)
}

// Verify Verifies that the message was signed using the public key
func Verify(message []byte, signature []byte, publicKey *rsa.PublicKey) error {
	hashed := generateHash(message)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
}

// VerifyFile Verifies that the file was signed using the public key
func VerifyFile(path string, stampPath string, publicKey *rsa.PublicKey) error {
	data, err := ioutil.ReadFile(path)

	if err != nil {
		return err
	}

	stampData, err := ioutil.ReadFile(stampPath)

	if err != nil {
		return err
	}

	return Verify(data, stampData, publicKey)
}

// Encrypt Encrypts the message using the public key
func Encrypt(message []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	rnd := rand.Reader
	return rsa.EncryptPKCS1v15(rnd, publicKey, message)
}

// EncryptFile Encrypts the file using the public key and return the encrypted bytes
func EncryptFile(path string, publicKey *rsa.PublicKey) ([]byte, error) {
	data, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	return Encrypt(data, publicKey)
}

// Decrypt Decrypts the message using the private key
func Decrypt(message []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptPKCS1v15(nil, privateKey, message)
}

// DecryptFile Decrypt the file using the private key and return the decrypted bytes
func DecryptFile(path string, privateKey *rsa.PrivateKey) ([]byte, error) {
	data, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	return Decrypt(data, privateKey)
}
