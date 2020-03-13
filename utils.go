package simplersa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"

	"golang.org/x/crypto/ssh"
)

// LoadPrivateKey Load the private key from a file
func LoadPrivateKey(rsaPrivateKeyPath, rsaPrivateKeyPassword string) (*rsa.PrivateKey, error) {
	priv, err := ioutil.ReadFile(rsaPrivateKeyPath)
	if err != nil {
		return nil, err
	}

	// TODO: Add support for private key with password
	key, err := ssh.ParseRawPrivateKey(priv)

	if err != nil {
		return nil, err
	}

	privateKey := key.(*rsa.PrivateKey)
	return privateKey, nil
}

// LoadPublicKey Load the public key from the file
func LoadPublicKey(rsaPublicKeyPath string) (*rsa.PublicKey, error) {
	// Based on: https://gist.github.com/jshap70/259a87a7146393aab5819873a193b88c
	pub, err := ioutil.ReadFile(rsaPublicKeyPath)
	if err != nil {
		return nil, errors.New("No RSA public key found")
	}

	block, _ := pem.Decode([]byte(pub))

	if err != nil {
		return nil, err
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return parsedKey.(*rsa.PublicKey), nil
}
