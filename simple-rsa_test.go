package simplersa

import (
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type TestSuite struct {
	suite.Suite
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func signAndVerify(msg, verifyMsg string) error {
	// Load the private and public keys
	privKey, pubKey := loadTestKeys()

	// Stamp the message
	stampedMessage, err := Sign([]byte(msg), privKey)

	if err != nil {
		return err
	}

	error := Verify([]byte(verifyMsg), stampedMessage, pubKey)
	return error
}

func TestSign(t *testing.T) {
	privKey, _ := loadTestKeys()
	msg := "This is a message to stamp"

	stampedMessage, err := Sign([]byte(msg), privKey)

	assert.NoError(t, err)
	assert.NotNil(t, stampedMessage)
}

func TestSignFile(t *testing.T) {
	privKey, _ := loadTestKeys()
	stampedMessage, err := SignFile(fileToEncrypt, privKey)

	assert.NoError(t, err)
	assert.NotNil(t, stampedMessage)
}

func TestVerify(t *testing.T) {
	privKey, pubKey := loadTestKeys()
	msg := "This is a message to verify"

	stampedMessage, err := Sign([]byte(msg), privKey)

	assert.NoError(t, err)
	assert.Nil(t, Verify([]byte(msg), []byte(stampedMessage), pubKey))
}

func TestVerifyFile(t *testing.T) {
	_, pubKey := loadTestKeys()
	err := VerifyFile(fileToEncrypt, stampedFile, pubKey)

	assert.NoError(t, err)
}

func TestSignAndVerifyWithValidMessage(t *testing.T) {
	msg := "This is a nice"
	assert.Nil(t, signAndVerify(msg, msg))
}

func TestSignAndVerifyWithInvalidMessage(t *testing.T) {
	msg := "This is a nice message"
	invalidMessage := "This is an incorrect message"
	assert.NotNil(t, signAndVerify(msg, invalidMessage))
}

func TestEncrypt(t *testing.T) {
	_, pubKey := loadTestKeys()
	msg := "This is a message to encrypt"
	encrypted, err := Encrypt([]byte(msg), pubKey)

	assert.NoError(t, err)
	assert.NotNil(t, encrypted)
}

func TestEncryptFile(t *testing.T) {
	_, pubKey := loadTestKeys()
	data, err := EncryptFile(fileToEncrypt, pubKey)
	assert.NoError(t, err)
	assert.NotNil(t, data)
}

func TestDecrypt(t *testing.T) {
	privKey, pubKey := loadTestKeys()
	msg := "This is a decrypted message"

	encrypted, err := Encrypt([]byte(msg), pubKey)

	assert.NoError(t, err)
	decrypted, err := Decrypt(encrypted, privKey)

	assert.NoError(t, err)
	assert.Equal(t, []byte(msg), decrypted)
}

func TestDecryptFile(t *testing.T) {
	privKey, _ := loadTestKeys()

	decrypted, err := DecryptFile(fileToDecrypt, privKey)
	assert.NoError(t, err)
	assert.Equal(t, "This file is used for testing messages", string(decrypted))
}
