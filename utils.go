package simplersa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"

	"golang.org/x/crypto/ssh"
)

// LoadPrivateKeyFromFile Load the private key from a file
func LoadPrivateKeyFromFile(rsaPrivateKeyPath, rsaPrivateKeyPassword string) (*rsa.PrivateKey, error) {
	priv, err := ioutil.ReadFile(rsaPrivateKeyPath)
	if err != nil {
		return nil, err
	}

	return LoadPrivateKey(priv)
}

// LoadPrivateKey Load the private key from the specified bytes
func LoadPrivateKey(bytes []byte) (*rsa.PrivateKey, error) {
	// TODO: Add support for private key with password
	key, err := ssh.ParseRawPrivateKey(bytes)

	if err != nil {
		return nil, err
	}

	privateKey := key.(*rsa.PrivateKey)
	return privateKey, nil
}

// LoadPublicKeyFromFile Load the public key from the file
func LoadPublicKeyFromFile(rsaPublicKeyPath string) (*rsa.PublicKey, error) {
	// Based on: https://gist.github.com/jshap70/259a87a7146393aab5819873a193b88c
	pub, err := ioutil.ReadFile(rsaPublicKeyPath)
	if err != nil {
		return nil, errors.New("No RSA public key found")
	}

	return LoadPublicKey(pub)
}

// LoadPublicKeyLoad the public key from the key bytes
func LoadPublicKey(bytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(bytes))

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return parsedKey.(*rsa.PublicKey), nil
}
