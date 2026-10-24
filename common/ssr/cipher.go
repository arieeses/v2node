// Package ssr implements a self-contained ShadowsocksR server (stream ciphers +
// SSR protocol/obfs plugins) and bridges each accepted stream into the Xray
// dispatcher, so per-user accounting/limits/routing run through the same
// pipeline as the other protocols. It has no external SSR dependency: the
// ciphers use crypto/cipher, the KDF is EVP_BytesToKey (MD5), and the protocol
// framing is reimplemented to interoperate byte-for-byte with Clash/mihomo SSR
// clients (verified against mihomo's transport/ssr).
//
// Multi-user is single-port-multi-user (SPMU): all users share the node cipher
// password; the SSR auth protocol carries a per-user userID the server maps to
// that user's key in O(1) — no per-user trial decryption.
package ssr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"fmt"

	"golang.org/x/crypto/chacha20"
)

// kdf is shadowsocks' key derivation (OpenSSL EVP_BytesToKey with MD5).
func kdf(password string, keyLen int) []byte {
	var b, prev []byte
	for len(b) < keyLen {
		h := md5.New()
		h.Write(prev)
		h.Write([]byte(password))
		prev = h.Sum(nil)
		b = append(b, prev...)
	}
	return b[:keyLen]
}

// cipherSpec describes a stream cipher's key/iv sizes and how to build the
// keystream for a given key+iv.
type cipherSpec struct {
	keySize int
	ivSize  int
	newEnc  func(key, iv []byte) (cipher.Stream, error)
	newDec  func(key, iv []byte) (cipher.Stream, error)
}

func cfb(key, iv []byte) (cipher.Stream, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBEncrypter(b, iv), nil
}
func cfbDec(key, iv []byte) (cipher.Stream, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBDecrypter(b, iv), nil
}
func ctr(key, iv []byte) (cipher.Stream, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(b, iv), nil
}
func rc4md5(key, iv []byte) (cipher.Stream, error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	return rc4.NewCipher(h.Sum(nil))
}
func chacha(key, iv []byte) (cipher.Stream, error) {
	return chacha20.NewUnauthenticatedCipher(key, iv)
}

var cipherSpecs = map[string]cipherSpec{
	"aes-128-cfb":    {16, 16, cfb, cfbDec},
	"aes-192-cfb":    {24, 16, cfb, cfbDec},
	"aes-256-cfb":    {32, 16, cfb, cfbDec},
	"aes-128-ctr":    {16, 16, ctr, ctr},
	"aes-192-ctr":    {24, 16, ctr, ctr},
	"aes-256-ctr":    {32, 16, ctr, ctr},
	"rc4-md5":        {16, 16, rc4md5, rc4md5},
	"chacha20-ietf":  {32, 12, chacha, chacha},
}

func newCipherSpec(name string) (cipherSpec, error) {
	s, ok := cipherSpecs[name]
	if !ok {
		return cipherSpec{}, fmt.Errorf("ssr: unsupported cipher %q", name)
	}
	return s, nil
}
