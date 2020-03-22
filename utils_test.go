package simplersa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadPrivateKey(t *testing.T) {
	key, err := LoadPrivateKeyFromFile("./test_keys/test_key.priv", "")

	if !assert.Nil(t, err) {
		return
	}

	assert.NotNil(t, key, "Key is empty!")
}

func TestLoadPublicKey(t *testing.T) {
	key, err := LoadPublicKeyFromFile("./test_keys/test_key.pub")

	if !assert.Nil(t, err) {
		return
	}

	assert.NotNil(t, key, "Key is empty!")
}
