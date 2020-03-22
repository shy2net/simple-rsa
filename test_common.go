package simplersa

import "crypto/rsa"

/**
This file contains common test consts and utils.
**/

/**
 * These files are used to encrypt and contains a stamp.
 */
const fileToEncrypt = "./test_assets/msg.txt"
const fileToDecrypt = "./test_assets/msg.encrypted"
const stampedFile = "./test_assets/msg.signed"
const privateKeyFile = "./test_keys/test_key.priv"
const publicKeyFile = "./test_keys/test_key.pub"

func loadTestKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	privKey, _ := LoadPrivateKeyFromFile(privateKeyFile, "")
	pubKey, _ := LoadPublicKeyFromFile(publicKeyFile)
	return privKey, pubKey
}
