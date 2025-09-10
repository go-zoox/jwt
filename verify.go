package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	typ "github.com/go-zoox/core-utils/type"
	"github.com/go-zoox/crypto/hmac"
)

// VerifyOptions is the options for Verify
type VerifyOptions struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	NotBefore int64  `json:"nbf"`
	IssuedAt  int64  `json:"iat"`
	JWTID     string `json:"jti"`
}

// parseRSAPublicKey parses an RSA public key from PEM format
func parseRSAPublicKey(publicKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}

	var key interface{}
	var err error

	switch block.Type {
	case "PUBLIC KEY":
		key, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaKey, nil
}

// parseECDSAPublicKey parses an ECDSA public key from PEM format
func parseECDSAPublicKey(publicKeyPEM string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}

	var key interface{}
	var err error

	switch block.Type {
	case "PUBLIC KEY":
		key, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "EC PUBLIC KEY":
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	return ecdsaKey, nil
}

// decodeECDSASignature decodes ECDSA signature from concatenated r and s bytes
func decodeECDSASignature(signature []byte) (*big.Int, *big.Int, error) {
	if len(signature)%2 != 0 {
		return nil, nil, fmt.Errorf("invalid signature length")
	}

	halfLen := len(signature) / 2
	r := new(big.Int).SetBytes(signature[:halfLen])
	s := new(big.Int).SetBytes(signature[halfLen:])

	return r, s, nil
}

// Verify verifies data with secret
func Verify(secret string, token string, options ...*VerifyOptions) (header *Header, payload *typ.Value, err error) {
	var opt *VerifyOptions = nil
	if len(options) > 0 && options[0] != nil {
		opt = options[0]
	}

	headerX, payloadX, headerBase64, payloadBase64, signatureX, err := Parse(token)
	if err != nil {
		return nil, nil, err
	}

	var signature string
	var isValid bool
	switch headerX.Algorithm {
	case AlgHS256:
		signature = hmac.Sha256(secret, fmt.Sprintf("%s.%s", headerBase64, payloadBase64), "base64")
		isValid = signature == signatureX
	case AlgHS384:
		signature = hmac.Sha384(secret, fmt.Sprintf("%s.%s", headerBase64, payloadBase64), "base64")
		isValid = signature == signatureX
	case AlgHS512:
		signature = hmac.Sha512(secret, fmt.Sprintf("%s.%s", headerBase64, payloadBase64), "base64")
		isValid = signature == signatureX
	case AlgRS256:
		publicKey, err := parseRSAPublicKey(secret)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse RSA public key: %v", err)
		}

		// Decode the signature
		signatureBytes, err := base64.RawURLEncoding.DecodeString(signatureX)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode signature: %v", err)
		}

		// Create hash of the message
		hasher := sha256.New()
		hasher.Write([]byte(fmt.Sprintf("%s.%s", headerBase64, payloadBase64)))
		hashed := hasher.Sum(nil)

		// Verify the signature
		err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, signatureBytes)
		isValid = err == nil
	case AlgRS384:
		publicKey, err := parseRSAPublicKey(secret)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse RSA public key: %v", err)
		}

		// Decode the signature
		signatureBytes, err := base64.RawURLEncoding.DecodeString(signatureX)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode signature: %v", err)
		}

		// Create hash of the message
		hasher := sha512.New384()
		hasher.Write([]byte(fmt.Sprintf("%s.%s", headerBase64, payloadBase64)))
		hashed := hasher.Sum(nil)

		// Verify the signature
		err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA384, hashed, signatureBytes)
		isValid = err == nil
	case AlgRS512:
		publicKey, err := parseRSAPublicKey(secret)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse RSA public key: %v", err)
		}

		// Decode the signature
		signatureBytes, err := base64.RawURLEncoding.DecodeString(signatureX)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode signature: %v", err)
		}

		// Create hash of the message
		hasher := sha512.New()
		hasher.Write([]byte(fmt.Sprintf("%s.%s", headerBase64, payloadBase64)))
		hashed := hasher.Sum(nil)

		// Verify the signature
		err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA512, hashed, signatureBytes)
		isValid = err == nil
	case AlgES256:
		publicKey, err := parseECDSAPublicKey(secret)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse ECDSA public key: %v", err)
		}

		// Decode the signature
		signatureBytes, err := base64.RawURLEncoding.DecodeString(signatureX)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode signature: %v", err)
		}

		// Decode r and s from signature
		r, s, err := decodeECDSASignature(signatureBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode ECDSA signature: %v", err)
		}

		// Create hash of the message
		hasher := sha256.New()
		hasher.Write([]byte(fmt.Sprintf("%s.%s", headerBase64, payloadBase64)))
		hashed := hasher.Sum(nil)

		// Verify the signature
		isValid = ecdsa.Verify(publicKey, hashed, r, s)
	case AlgES384:
		publicKey, err := parseECDSAPublicKey(secret)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse ECDSA public key: %v", err)
		}

		// Decode the signature
		signatureBytes, err := base64.RawURLEncoding.DecodeString(signatureX)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode signature: %v", err)
		}

		// Decode r and s from signature
		r, s, err := decodeECDSASignature(signatureBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode ECDSA signature: %v", err)
		}

		// Create hash of the message
		hasher := sha512.New384()
		hasher.Write([]byte(fmt.Sprintf("%s.%s", headerBase64, payloadBase64)))
		hashed := hasher.Sum(nil)

		// Verify the signature
		isValid = ecdsa.Verify(publicKey, hashed, r, s)
	case AlgES512:
		publicKey, err := parseECDSAPublicKey(secret)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse ECDSA public key: %v", err)
		}

		// Decode the signature
		signatureBytes, err := base64.RawURLEncoding.DecodeString(signatureX)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode signature: %v", err)
		}

		// Decode r and s from signature
		r, s, err := decodeECDSASignature(signatureBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode ECDSA signature: %v", err)
		}

		// Create hash of the message
		hasher := sha512.New()
		hasher.Write([]byte(fmt.Sprintf("%s.%s", headerBase64, payloadBase64)))
		hashed := hasher.Sum(nil)

		// Verify the signature
		isValid = ecdsa.Verify(publicKey, hashed, r, s)
	case AlgPS256:
		publicKey, err := parseRSAPublicKey(secret)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse RSA public key: %v", err)
		}

		// Decode the signature
		signatureBytes, err := base64.RawURLEncoding.DecodeString(signatureX)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode signature: %v", err)
		}

		// Create hash of the message
		hasher := sha256.New()
		hasher.Write([]byte(fmt.Sprintf("%s.%s", headerBase64, payloadBase64)))
		hashed := hasher.Sum(nil)

		// Verify the signature using RSA-PSS
		err = rsa.VerifyPSS(publicKey, crypto.SHA256, hashed, signatureBytes, nil)
		isValid = err == nil
	case AlgPS384:
		publicKey, err := parseRSAPublicKey(secret)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse RSA public key: %v", err)
		}

		// Decode the signature
		signatureBytes, err := base64.RawURLEncoding.DecodeString(signatureX)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode signature: %v", err)
		}

		// Create hash of the message
		hasher := sha512.New384()
		hasher.Write([]byte(fmt.Sprintf("%s.%s", headerBase64, payloadBase64)))
		hashed := hasher.Sum(nil)

		// Verify the signature using RSA-PSS
		err = rsa.VerifyPSS(publicKey, crypto.SHA384, hashed, signatureBytes, nil)
		isValid = err == nil
	case AlgPS512:
		publicKey, err := parseRSAPublicKey(secret)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse RSA public key: %v", err)
		}

		// Decode the signature
		signatureBytes, err := base64.RawURLEncoding.DecodeString(signatureX)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode signature: %v", err)
		}

		// Create hash of the message
		hasher := sha512.New()
		hasher.Write([]byte(fmt.Sprintf("%s.%s", headerBase64, payloadBase64)))
		hashed := hasher.Sum(nil)

		// Verify the signature using RSA-PSS
		err = rsa.VerifyPSS(publicKey, crypto.SHA512, hashed, signatureBytes, nil)
		isValid = err == nil
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %s", headerX.Algorithm)
	}

	if !isValid {
		return nil, nil, errors.New("invalid signature")
	}

	if opt != nil {
		if opt.Issuer != "" && payloadX.Get("iss").String() != opt.Issuer {
			return nil, nil, fmt.Errorf("invalid issuer: %s", payloadX.Get("iss").String())
		}

		if opt.Subject != "" && payloadX.Get("sub").String() != opt.Subject {
			return nil, nil, fmt.Errorf("invalid subject: %s", payloadX.Get("sub").String())
		}

		if opt.Audience != "" && payloadX.Get("aud").String() != opt.Audience {
			return nil, nil, fmt.Errorf("invalid audience: %s", payloadX.Get("aud").String())
		}
	}

	if payloadX.Has("exp") {
		expiredAtFloat64, err := payloadX.Get("exp").Float64E()
		if err != nil {
			return nil, nil, fmt.Errorf("invalid expiredAt: %s", err)
		}

		now := time.Now().Unix()
		if expiredAtFloat64 < float64(now) {
			return nil, nil, fmt.Errorf("token expired")
		}
	}

	return headerX, payloadX, nil
}
