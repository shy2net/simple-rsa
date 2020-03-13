package simplersa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadPrivateKey(t *testing.T) {
	key, err := LoadPrivateKey("./test_keys/test_key.priv", "")

	if !assert.Nil(t, err) {
		return
	}

	assert.NotNil(t, key, "Key is empty!")
}

func TestLoadPublicKey(t *testing.T) {
	key, err := LoadPublicKey("./test_keys/test_key.pub")

	if !assert.Nil(t, err) {
		return
	}

	assert.NotNil(t, key, "Key is empty!")
}
