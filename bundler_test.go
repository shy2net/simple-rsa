package simplersa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignAndBundle(t *testing.T) {
	privateKey, _ := loadTestKeys()
	msg := "This is a message to sign"

	bundle, err := SignAndBundle([]byte(msg), privateKey)

	assert.NoError(t, err)
	assert.NotNil(t, bundle)
}

func TestSignAndBundleFile(t *testing.T) {
	privateKey, _ := loadTestKeys()

	bundle, err := SignAndBundleFile(fileToDecrypt, privateKey)

	assert.NoError(t, err)
	assert.NotNil(t, bundle)
}

func TestVerifyAndBundle(t *testing.T) {
	privateKey, publicKey := loadTestKeys()

	msg := "This is a message to verify"
	bundle, err := SignAndBundle([]byte(msg), privateKey)

	assert.NoError(t, err)
	verifiedMsg, err := VerifyAndUnbundle(bundle, publicKey)

	assert.NoError(t, err)
	assert.Equal(t, msg, string(verifiedMsg))
}
