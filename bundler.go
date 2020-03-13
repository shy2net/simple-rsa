package simplersa

import (
	"archive/tar"
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"io"
	"io/ioutil"
)

const bundleStampFileName = "signature.stamp"
const bundleMessageFileName = "message.base64"

// Bundle a signed message with it's encoded bytes
func bundleSignedWithEncodedMessage(signed, encoded []byte) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	bundleFiles := []struct {
		Name string
		Body []byte
	}{
		{bundleStampFileName, signed},
		{bundleMessageFileName, encoded},
	}

	for _, file := range bundleFiles {
		hdr := &tar.Header{
			Name: file.Name,
			Mode: 0600,
			Size: int64(len(file.Body)),
		}

		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}

		if _, err := tw.Write([]byte(file.Body)); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// SignAndBundle Signs the message, decodes it using Base64 and bundles it with the signature into a tar file
func SignAndBundle(message []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	// Sign the message
	signed, err := Sign(message, privateKey)

	if err != nil {
		return nil, err
	}

	// Encode it into base 64
	encoded := []byte(base64.StdEncoding.EncodeToString(message))

	// Return the bundled signed file with it's encoded message
	return bundleSignedWithEncodedMessage(signed, encoded)
}

// SignAndBundleFile signs the provided file, encodes it into base64, and bundles it
func SignAndBundleFile(path string, privatekey *rsa.PrivateKey) ([]byte, error) {
	privateKey, _ := loadTestKeys()
	data, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	return SignAndBundle(data, privateKey)
}

// VerifyAndUnbundle Verifies that the bundle contains the signed message and extracts the message from it.
func VerifyAndUnbundle(bundle []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	// Create a buffer to read from the tar bytes
	var buf bytes.Buffer

	// Write the bytes into the buffer
	buf.Write(bundle)

	// Extract the bundle
	tr := tar.NewReader(&buf)

	var encodedMessageBuffer bytes.Buffer
	var stampBuffer bytes.Buffer

	for {
		// Read the next header
		hdr, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}

		if err != nil {
			return nil, err
		}

		if hdr.Name == bundleStampFileName {
			if _, err := io.Copy(&stampBuffer, tr); err != nil {
				return nil, err
			}
		} else if hdr.Name == bundleMessageFileName {
			if _, err := io.Copy(&encodedMessageBuffer, tr); err != nil {
				return nil, err
			}
		}
	}

	bundleStamp := stampBuffer.Bytes()
	bundleEncodedMessage := encodedMessageBuffer.Bytes()
	bundleDecodedMessage, err := base64.StdEncoding.DecodeString(string(bundleEncodedMessage))

	if err != nil {
		return nil, err
	}

	if err := Verify(bundleDecodedMessage, []byte(bundleStamp), publicKey); err != nil {
		return nil, err
	}

	return bundleDecodedMessage, nil
}

// VerifyAndUnbundleFile Verifies that the bundle and encoded message was stamped, if so, return the bytes of the message
func VerifyAndUnbundleFile(path string, publicKey *rsa.PublicKey) ([]byte, error) {
	data, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	return VerifyAndUnbundle(data, publicKey)
}
