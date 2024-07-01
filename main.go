package main

import "C"

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
)

var (
	aesKey256          [32]byte
	aesIV              []byte
	errUnpaddingFailed = errors.New("decrypt failed, perhaps you are using different keys to encrypt and decrypt")
	baseEncoder        = base32.StdEncoding.WithPadding(base32.NoPadding)
)

const (
	defaultAESKey   = "winter is coming"
	defaultIVString = "long live friendship"
)

// NewKeyText return an KeyText instance.
func NewKeyText(key, text string) *KeyText {
	return &KeyText{
		key:  key,
		text: text,
	}
}

// KeyText is the key and text/ciphertext for encryption or decryption.
type KeyText struct {
	key  string
	text string
}

// GetKey returns the key
func (kt *KeyText) GetKey() string {
	return kt.key
}

// GetText returns the text
func (kt *KeyText) GetText() string {
	return kt.text
}

// Encrypt encrypts the text to ciphertext using key, if key is empty, a default key is used.
// export Encrypt
func Encrypt(kt *KeyText) (ciphertext string, err error) {
	// padding
	var textBytes = pkcs7Padding([]byte(kt.GetText()), aes.BlockSize)
	fmt.Printf("textBytes = %v\n", textBytes)
	var keyBytes = []byte(kt.GetKey())
	fmt.Printf("keyBytes = %v\n", keyBytes)
	var ciphertextBytes []byte
	// encrypt
	if ciphertextBytes, err = encrypt(keyBytes, textBytes); nil != err {
		return
	}
	fmt.Printf("ciphertext Bytes = %v\n", ciphertextBytes)
	ciphertext = base32Encode(ciphertextBytes) // base32 encode
	return
}

// Decrypt decrypts the ciphertext to text using key, if key is empty, a default key is used.
// export Decrypt
func Decrypt(kt *KeyText) (text string, err error) {
	var keyBytes = []byte(kt.GetKey())
	var ciphertextBytes []byte
	// base32 decode
	if ciphertextBytes, err = base32Decode(kt.GetText()); nil != err {
		return
	}
	// decrypt
	ciphertextBytes, err = decrypt(keyBytes, ciphertextBytes)
	if nil != err {
		return
	}
	// unpadding
	ciphertextBytes, err = pkcs7Unpadding(ciphertextBytes)
	text = string(ciphertextBytes)
	return
}

func encrypt(key []byte, text []byte) (ciphertext []byte, err error) {
	ciphertext = make([]byte, len(text))
	block, err := newBlock(key)
	if nil != err {
		return
	}
	mode := cipher.NewCBCEncrypter(block, aesIV)
	mode.CryptBlocks(ciphertext, text)
	return
}

func decrypt(key []byte, ciphertext []byte) (text []byte, err error) {
	text = make([]byte, len(ciphertext))
	block, err := newBlock(key)
	if nil != err {
		return
	}
	mode := cipher.NewCBCDecrypter(block, aesIV)
	mode.CryptBlocks(text, ciphertext)
	return
}

func newBlock(key []byte) (block cipher.Block, err error) {
	var key256 [32]byte
	if len(key) == 0 {
		key256 = aesKey256
	} else {
		key256 = sha256.Sum256(key)
	}
	key = key256[:]
	block, err = aes.NewCipher(key)
	return
}

// pkcs7Padding use PKCS7 to fill data blcok
// https://tools.ietf.org/html/rfc5652#section-6.3
func pkcs7Padding(text []byte, blockSize int) []byte {
	padding := blockSize - len(text)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	// padtext := bytes.Repeat([]byte{byte(0)}, padding)
	return append(text, padtext...)
}

// pkcs7Unpadding use PKCS7 to unpad data blcok
func pkcs7Unpadding(text []byte) ([]byte, error) {
	length := len(text)
	unpadding := int(text[length-1])
	var rest = length - unpadding
	if rest < 0 {
		return text, errUnpaddingFailed
	}
	return text[:rest], nil
}

func base32Encode(data []byte) string {
	return baseEncoder.EncodeToString(data)
}

func base32Decode(s string) ([]byte, error) {
	return baseEncoder.DecodeString(s)
}

func main() {
	aesKey256 = sha256.Sum256([]byte(defaultAESKey))
	ivBytes := sha256.Sum256([]byte(defaultIVString))
	aesIV = ivBytes[:aes.BlockSize]
	fmt.Printf("aesIV = %d\n", aesIV)
	// [153  116   28    119   195   74    104   249   13    114   118   218   56    172   51    247]
	// 0x99, 0x74, 0x1C, 0x77, 0xC3, 0x4A, 0x68, 0xF9, 0x0D, 0x72, 0x76, 0xDA, 0x38, 0xAC, 0x33, 0xF7

	text := "helloworld"
	fmt.Printf("original text = %v\n", text)
	kt := NewKeyText("hytkey", text)
	ciphertext, _ := Encrypt(kt)
	fmt.Printf("ciphertext = %v\n", ciphertext)
	kt = NewKeyText("hytkey", ciphertext)
	text1, _ := Decrypt(kt)
	fmt.Printf("decrypted text1 = %v\n", text1)
}
