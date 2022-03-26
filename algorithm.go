package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"

	"github.com/pkg/errors"
)

type Algorithm struct {
	Name string
	Hash hash.Hash
}

func (a *Algorithm) Sign(text []byte) ([]byte, error) {
	_, err := a.Hash.Write(text)
	if err != nil {
		return nil, errors.Wrap(err, "unable to write to "+a.Name)
	}

	signature := a.Hash.Sum(nil)
	a.Hash.Reset()
	return signature, nil
}

func (a *Algorithm) Verify(text []byte, signature []byte) (bool, error) {
	_, err := a.Hash.Write(text)
	if err != nil {
		return false, errors.Wrap(err, "unable to write to "+a.Name)
	}

	_signature := a.Hash.Sum(nil)
	_signatureB64 := base64.RawURLEncoding.EncodeToString(_signature)
	if _signatureB64 != string(signature) {
		return false, errors.New("invalid signature")
	}

	return true, nil
}

func HmacSha256(secret string) *Algorithm {
	return &Algorithm{
		Name: "HS256",
		Hash: hmac.New(sha256.New, []byte(secret)),
	}
}

func HmacSha512(secret string) *Algorithm {
	return &Algorithm{
		Name: "HS512",
		Hash: hmac.New(sha512.New, []byte(secret)),
	}
}

func HmacSha384(secret string) *Algorithm {
	return &Algorithm{
		Name: "HS384",
		Hash: hmac.New(sha512.New384, []byte(secret)),
	}
}
