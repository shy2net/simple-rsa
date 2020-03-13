## simple-rsa - A simple to use RSA for Go

simple-rsa is an easy to use RSA library for Go.
It allows simple encrypt, sign, decrypt and verify on data without
knowing the "guts" of RSA, just import the library and use RSA easily.

One of the main features of simple-rsa is that you can easily sign a file, bundle the signature and file into a tar file.
Which later you can unbundle, check if the file was signed by you and read the content which was signed for (the original message which was signed).

### Generating keys using openssl

In order to generate public\private keys, you can use the `openssl` utility:

```bash
# Generate private key
openssl genrsa -out test_key.priv 2048
# Generate related public key
openssl rsa -in test_key.priv -out test_key.pub -pubout -outform PEM
```


### Using this library

If you are planning to use the bundle function, which bundle both the signature and the original file, you should take into account that the bundle will be saved compressed into a tar file.

The tar file will contain 2 files:

- signature.stamp - This signature itself which was signed by the private key.
- message.base64 - Contains the original file, encoded in base64.

When using the VerifyAndUnbundle method, it will verify that the message (message.base64) has the same hash as the signature.stamp
we signed using the private key. If so, it will return the bytes extracted, decoded by base64. If verification fails, it will return an error.


#### Signing and bundling a file with the signature (to a .tar format)

This example will sign the file provided, bundle it into a .tar file with both the signed file and the original file.
After doing so, it will save the bundle into a file, and then validate and extract the file back, if it was verified.

```go
package main

import (
    "fmt"
    "io/ioutil"

    "github.com/shy2net/simple-rsa"
)

func main() {
    // Load the private key
    privKey, _ := simplersa.LoadPrivateKey("keys/my_key.priv")

    // Sign the file, bundle it with the stamp
    signed, _ := simplersa.SignAndBundleFile("./file_to_sign.txt", privateKey)

    // Now save the signed bundle
    ioutil.WriteFile("signed.bundle.tar", )

    // Load the public key
    pubKey, _ := simplersa.LoadPublicKey("keys/my_key.pub")

    // Verifies if this bundle was signed, and extract the file we have signed
    verifiedFileBytes, err := VerifyAndUnbundle(bundle, publicKey)

    if err != nil {
        fmt.Println("Failed to verify bundle!")
        return
    }

    fmt.Println("File was verified and extracted with the following content:")
    fmt.Println(string(verifiedFileBytes))
}
```



#### Signing and verifying files

This example will sign a file, store the signature and then verify it with the original file.

```go
package main

import (
    "fmt"
    "io/ioutil"

    "github.com/shy2net/simple-rsa"
)

func main() {
    // Load the private key
    privKey, _ := simplersa.LoadPrivateKey("keys/my_key.priv")

    // Sign the specified file, this would return the file with it's signed bytes
    signed, _ := simplersa.SignFile("file.txt", privKey))

    // Now save the signed file
    ioutil.WriteFile("file.signed", )

    // Load the public key
    pubKey, _ := simplersa.LoadPublicKey("keys/my_key.pub")

    // Verify if the provided file plaintext file was signed by comparing it using the 'file.signed' we have generated
    simplersa.VerifyFile("file_to_validate.txt", "file.signed", pubKey)
}
```


#### Encrypting and decrypting files

This example will encrypt the file using the public key, and decrypt it using the private key.

```go
package main

import (
    "fmt"
    "io/ioutil"

    "github.com/shy2net/simple-rsa"
)

func main() {
    // Load the public key
    pubKey, _ := simplersa.LoadPublicKey("keys/my_key.pub")

    // Encrypt the file and get the encrypted bytes
    encrypted, _ := simplersa.EncryptFile("file_to_encrypt.txt", pubKey)

    // Now save the encrypted bytes into a file
    ioutil.WriteFile("file.encrypted.txt", encrypted)

    // Load the private key
    privKey, _ := simplersa.LoadPrivateKey("keys/my_key.priv")

    // Decrypt the file using the private key
    decrypted, _ := simplersa.DecryptFile("file.txt", privKey))

    // Print out the decrypted message
    fmt.Printf(decrypted)
}
```