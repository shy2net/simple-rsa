package simplersa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadPrivateKeyFile(t *testing.T) {
	key, err := LoadPrivateKeyFromFile("./test_keys/test_key.priv", "")

	if !assert.Nil(t, err) {
		return
	}

	assert.NotNil(t, key, "Key is empty!")
}

func TestLoadPrivateKey(t *testing.T) {
	privateKeyStr := `-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAtri83Wi7Z9LuLrqlOknhWS9tFihcmDoHKf6/mvwmMLpy6K5D
nFSXFAdYbHI60a7dG/5dmoeVq6WcbaJz//kzS5ka2IQUy94s1V8KjObtTjXGtA+m
bGEF8Y+SGCRTvVMgT7bIalwcAT8/C8S42hoqp66q1oFd3WyGPjYX3Udjv0NMEGok
tC7b9qUW3SPXkvWZvL5q5Oce7Q6bGYkx7CvHCQDuDMLz2kkAsjexmyd7dAaSS5Ho
va5eVDzRtvQmmr4clrMk4NRnYLrOstN15nZdVXfPw/ufqdgVI8lDO29YMtR3wPh9
3lnvyjDSIjLiSfYWwOhwefzB4i8LWVYVUSDKjQIDAQABAoIBAQCTZCetLitlz6cj
+JkJkMj/iRsksYAnpz9aJ81ldppT2kKQ4OlW9IE9vcMdD3PU6oofZ6sX2ODpqdiq
M04BIIK5K5KVLs4buWdO4rB/AlRQL17OpoUnjYge2CIP6VXHNYOt6ZJ3AT/x3ZO8
qX43KL5ZrrLN/2K5Fy6ehkHv1ANpJsDSfi3+hfkSvb8TqyFZpxZd/q5gK3gej5Ml
UXGvoWmw75IOqXpp5z2DdbtGTIUPuMhvknAPIeZoOGN95k9v3pKGrZaVF6OoDQ1L
9NRbgA7yXvASKs5R2XPJrAvV8bNlFu5/BorrHGgs6DC2pLMsr/SePwFeX1tKUFe0
V1xIWRGBAoGBAOsilu1kMEwB+HSKp4oogqk7dq+5+4whffNlA+MX0l/RAOARV1Cl
A24+rYiQ2QZmsvI4i8N1dohWoYsx7kcjaJuiIIcZpLUVwYo1Cb6KPSLhGlZlYjHH
TPuc5X6Gu7aoNKcIiYWIFbxPsBIO7FJcMrHgDoQ0nvifoo0mi/fBrTntAoGBAMbv
gWJ+pH+JQOdA5r7uMoioHLaT4fWo9P+aMaTE9sxVc4Aaz9un0YiUMQ8lqvAg4ujy
nlLfJ6jFRQWW9KzsgiyRfn/Mr7R2vKvemB9Y1O7Dinuz/3G/ABZPlYU66Nz9RPn2
5GRP+XIXQO65YITfFIE9cS+UiINtchYrAdwNVz8hAoGBANZpbzk/v+6/aUFUYlxQ
fn01VQ/+xwvMSp7UwUumoFZxLpwkE/vczRkNnI5Ijy4QHiNUPtZYWWMPpDVarY4/
EpfAqmqnjpL2KMsPfDg8tG0G2U5pGraLp35VXswWrjtsfL7HwSd7pV5XSBXfd83O
dwfOaU5S8ZeDceXGfaHKAV0tAoGBAJx/JaW6QuYhr3E82UkyUYa32X6373Y2KCY7
wvoACLbOMkKA1SvTZT6wdbeYxlSJSng/BNXkv2pBZf7zth+jHvS4sG8RMtgg4GPE
hJ+EXl5GbdbKzxVIUGU8zj81DKNsiqqp0xom3/Ek4evq4Uclxxe0oinwC0R5ANr3
kkruI8iBAoGBAIm1XvY+e1KFwIXUT2fp9ipfRs1TmRlhnDKyPFGX4RYURYSJqDzz
3qHvHTbEKLwBjtQBcO5qHhtPWePqViu5FpifnR4WqbWxMt0AyL1HLbhNv/FNMip7
9cDo2dHAdVzIcWbjyeeiMBLL1Pw0zW3KkHDUT4sekxvDHB9DAiCa9STF
-----END RSA PRIVATE KEY-----
`

	privateKey, err := LoadPrivateKey([]byte(privateKeyStr))

	assert.NoError(t, err)
	assert.NotNil(t, privateKey)
}

func TestLoadPublicKeyFile(t *testing.T) {
	key, err := LoadPublicKeyFromFile("./test_keys/test_key.pub")

	if !assert.Nil(t, err) {
		return
	}

	assert.NotNil(t, key, "Key is empty!")
}

func TestLoadPublicKey(t *testing.T) {
	publicKeyStr := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtri83Wi7Z9LuLrqlOknh
WS9tFihcmDoHKf6/mvwmMLpy6K5DnFSXFAdYbHI60a7dG/5dmoeVq6WcbaJz//kz
S5ka2IQUy94s1V8KjObtTjXGtA+mbGEF8Y+SGCRTvVMgT7bIalwcAT8/C8S42hoq
p66q1oFd3WyGPjYX3Udjv0NMEGoktC7b9qUW3SPXkvWZvL5q5Oce7Q6bGYkx7CvH
CQDuDMLz2kkAsjexmyd7dAaSS5Hova5eVDzRtvQmmr4clrMk4NRnYLrOstN15nZd
VXfPw/ufqdgVI8lDO29YMtR3wPh93lnvyjDSIjLiSfYWwOhwefzB4i8LWVYVUSDK
jQIDAQAB
-----END PUBLIC KEY-----
`

	publicKey, err := LoadPublicKey([]byte(publicKeyStr))

	assert.NoError(t, err)
	assert.NotNil(t, publicKey)
}
