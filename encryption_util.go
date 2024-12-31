package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"reflect"
	"time"
)

type EncryptedImageInformation struct {
	timestamp time.Time
	extension string
	length    uint32
	hash      []byte
}

func calculateRSAOverhead() (int, error) {
	cip, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		return -1, fmt.Errorf("failed to create cipher block: %s", err.Error())
	}
	gcm, err := cipher.NewGCM(cip)
	if err != nil {
		return -1, fmt.Errorf("failed to create gcm: %s", err.Error())
	}
	return gcm.Overhead(), nil
}

func LoadRSAPublicKey(rsaKeyPath string) (*rsa.PublicKey, error) {
	keyData, err := os.ReadFile(rsaKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA key: %s", err.Error())
	}
	pemData, _ := pem.Decode(keyData)
	if pemData == nil {
		return nil, fmt.Errorf("failed to parse PEM data")
	}
	publicKey, err := x509.ParsePKIXPublicKey(pemData.Bytes)
	if err != nil {
		return nil, fmt.Errorf("fauled to parse public key: %s", err.Error())
	}
	rsaPub, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not a RSA public key, it is instead %s", reflect.TypeOf(rsaPub).String())
	}
	return rsaPub, nil
}

func LoadRSAPrivateKey(rsaKeyPath string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(rsaKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA key: %s", err.Error())
	}
	pemData, _ := pem.Decode(keyData)
	if pemData == nil {
		return nil, fmt.Errorf("failed to parse PEM data")
	}
	rsaPriv, err := x509.ParsePKCS1PrivateKey(pemData.Bytes)
	if err != nil {
		privInterface, err := x509.ParsePKCS8PrivateKey(pemData.Bytes)
		if err != nil {
			return nil, fmt.Errorf("fauled to parse private key: %s", err.Error())
		}
		var ok bool
		if rsaPriv, ok = privInterface.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("not a RSA private key, it is instead %s", reflect.TypeOf(rsaPriv).String())
		}
	}
	return rsaPriv, nil
}

// tail of the data will look like this: [key, nonce, timestamp, extension, length, hash]

func decryptDataWithRSA(rsaKey string, verbose bool, dataBlock []byte, tailBlock []byte) ([]byte, *EncryptedImageInformation, error) {
	if verbose {
		fmt.Println("loading RSA private key")
	}
	rsaPriv, err := LoadRSAPrivateKey(rsaKey)
	if err != nil {
		return nil, nil, err
	}

	// decrypt tail block
	if verbose {
		fmt.Println("decrypting tail")
	}
	tail, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPriv, tailBlock)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt the tail block: %s", err.Error())
	}

	// prepare aes
	aesKey := tail[:32]
	cip, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher block: %s", err.Error())
	}
	gcm, err := cipher.NewGCM(cip)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create gcm: %s", err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce := tail[32 : 32+nonceSize]
	timetampBytes := tail[nonceSize+32 : nonceSize+40]
	extensionBytes := tail[nonceSize+40 : nonceSize+56]
	lengthBytes := tail[nonceSize+56 : nonceSize+60]
	hash := tail[nonceSize+60:]
	if len(hash) != 32 {
		return nil, nil, fmt.Errorf("wrong hash length, expected %d, got %d", 32, len(hash))
	}
	dataLength := binary.BigEndian.Uint32(lengthBytes)
	if dataLength > uint32(len(dataBlock)) {
		return nil, nil, fmt.Errorf("length of data %d is higher than available max length %d", dataLength, len(dataBlock))
	}
	unixTimestamp := int64(binary.BigEndian.Uint64(timetampBytes))
	info := &EncryptedImageInformation{
		timestamp: time.Unix(unixTimestamp, 0),
		extension: string(extensionBytes),
		length:    dataLength,
		hash:      hash,
	}

	if verbose {
		fmt.Printf("key: %x\tnonce: %x\n", aesKey, nonce)
		fmt.Println("decrypting data")
	}

	// decrypt data block
	plainData, err := gcm.Open(nil, nonce, dataBlock[:dataLength], nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt AES: %s", err.Error())
	}
	return plainData, info, nil
}

func encryptDataWithRSA(rsaKey string, verbose bool, data []byte, extension string, hashAndLength []byte) ([]byte, []byte, error) {
	if verbose {
		fmt.Println("loading RSA public key")
	}
	rsaPub, err := LoadRSAPublicKey(rsaKey)
	if err != nil {
		return nil, nil, err
	}

	aesKey := make([]byte, 32)
	if n, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return nil, nil, fmt.Errorf("failed to read rand data into AES key (%d out of %d bytes read): %s", n, len(aesKey), err.Error())
	}
	cip, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher block: %s", err.Error())
	}
	gcm, err := cipher.NewGCM(cip)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create gcm: %s", err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce := make([]byte, nonceSize)
	if n, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to read rand data into nonce (%d out of %d bytes read): %s", n, len(aesKey), err.Error())
	}
	if verbose {
		fmt.Printf("key: %x\tnonce: %x\n", aesKey, nonce)
		fmt.Println("encrypting data with AES128")
	}
	resultAndNonce := gcm.Seal(nonce, nonce, data, nil)
	aesNonce, aesResult := resultAndNonce[:nonceSize], resultAndNonce[nonceSize:]

	// prepare data for RSA
	binary.BigEndian.PutUint32(hashAndLength[:4], uint32(len(aesResult)))
	var extensionByte [16]byte
	var timestampByte [8]byte
	copy(extensionByte[:], []byte(extension))
	binary.BigEndian.PutUint64(timestampByte[:], uint64(time.Now().Unix()))
	rsaData := append(aesKey, aesNonce...)
	rsaData = append(rsaData, timestampByte[:]...)
	rsaData = append(rsaData, extensionByte[:]...)
	rsaData = append(rsaData, hashAndLength...)

	if verbose {
		fmt.Println("encrypting tail with RSA")
	}
	// encrypt RSA data
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, rsaData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt the tail data with RSA: %s", err.Error())
	}
	return aesResult, encrypted, nil
}
