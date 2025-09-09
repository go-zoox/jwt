package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/go-zoox/crypto/hmac"
)

// SignOptions is the options for Sign
type SignOptions struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	NotBefore int64  `json:"nbf"`
	IssuedAt  int64  `json:"iat"`
	JWTID     string `json:"jti"`
	Algorithm string

	// MaxAge is the token max age, default 2h
	MaxAge time.Duration
}

// parseRSAPrivateKey parses an RSA private key from PEM format
func parseRSAPrivateKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}

	var key interface{}
	var err error

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}

	return rsaKey, nil
}

// parseECDSAPrivateKey parses an ECDSA private key from PEM format
func parseECDSAPrivateKey(privateKeyPEM string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}

	var key interface{}
	var err error

	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA private key")
	}

	return ecdsaKey, nil
}

// encodeECDSASignature encodes ECDSA signature r and s as DER-encoded ASN.1 integers
func encodeECDSASignature(r, s *big.Int) []byte {
	// Convert r and s to byte slices
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Ensure they are the same length by padding with zeros if necessary
	maxLen := len(rBytes)
	if len(sBytes) > maxLen {
		maxLen = len(sBytes)
	}

	// Pad with zeros to make them the same length
	if len(rBytes) < maxLen {
		padding := make([]byte, maxLen-len(rBytes))
		rBytes = append(padding, rBytes...)
	}
	if len(sBytes) < maxLen {
		padding := make([]byte, maxLen-len(sBytes))
		sBytes = append(padding, sBytes...)
	}

	// Concatenate r and s
	return append(rBytes, sBytes...)
}

// Sign signs data with secret
func Sign(secret string, payload map[string]any, options ...*SignOptions) (string, error) {
	var opt *SignOptions = nil
	if len(options) > 0 && options[0] != nil {
		opt = options[0]
	}

	// default max age: 2h (7200s)
	var maxAge int64 = 7200
	if opt.MaxAge != 0 {
		maxAge = int64(opt.MaxAge.Seconds())
	}

	headerX := Header{
		Type:      "JWT",
		Algorithm: AlgHS256,
	}

	now := time.Now().Unix()
	// issuedAt default now
	issuedAt := now
	// expiredAt default 2 hour
	expiredAt := now + maxAge
	//
	payloadX := map[string]interface{}{
		"iss": "go-zoox",
	}

	if opt != nil {
		if opt.Algorithm != "" {
			headerX.Algorithm = opt.Algorithm
		}

		if opt.Issuer != "" {
			payloadX["iss"] = opt.Issuer
		}

		if opt.Subject != "" {
			payloadX["sub"] = opt.Subject
		}

		if opt.Audience != "" {
			payloadX["aud"] = opt.Audience
		}

		if opt.NotBefore > 0 {
			payloadX["nbf"] = opt.NotBefore
		}

		if opt.JWTID != "" {
			payloadX["jti"] = opt.JWTID
		}

		if opt.IssuedAt > 0 {
			issuedAt = opt.IssuedAt
			expiredAt = issuedAt + maxAge
		}

		if opt.ExpiresAt > 0 {
			expiredAt = opt.ExpiresAt
		}
	}

	payloadX["iat"] = issuedAt
	payloadX["exp"] = expiredAt

	// user data first
	for k, v := range payload {
		payloadX[k] = v
	}

	headerJSON, err := json.Marshal(headerX)
	if err != nil {
		return "", err
	}

	payloadJSON, err := json.Marshal(payloadX)
	if err != nil {
		return "", err
	}

	headerBase64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	var signature string
	switch headerX.Algorithm {
	case AlgHS256:
		signature = hmac.Sha256(secret, headerBase64+"."+payloadBase64, "base64")
	case AlgHS384:
		signature = hmac.Sha384(secret, headerBase64+"."+payloadBase64, "base64")
	case AlgHS512:
		signature = hmac.Sha512(secret, headerBase64+"."+payloadBase64, "base64")
	case AlgRS256:
		privateKey, err := parseRSAPrivateKey(secret)
		if err != nil {
			return "", fmt.Errorf("failed to parse RSA private key: %v", err)
		}

		// Create hash of the message
		hasher := sha256.New()
		hasher.Write([]byte(headerBase64 + "." + payloadBase64))
		hashed := hasher.Sum(nil)

		// Sign the hash
		signatureBytes, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, hashed)
		if err != nil {
			return "", fmt.Errorf("failed to sign with RSA: %v", err)
		}

		signature = base64.RawURLEncoding.EncodeToString(signatureBytes)
	case AlgRS384:
		privateKey, err := parseRSAPrivateKey(secret)
		if err != nil {
			return "", fmt.Errorf("failed to parse RSA private key: %v", err)
		}

		// Create hash of the message
		hasher := sha512.New384()
		hasher.Write([]byte(headerBase64 + "." + payloadBase64))
		hashed := hasher.Sum(nil)

		// Sign the hash
		signatureBytes, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA384, hashed)
		if err != nil {
			return "", fmt.Errorf("failed to sign with RSA: %v", err)
		}

		signature = base64.RawURLEncoding.EncodeToString(signatureBytes)
	case AlgRS512:
		privateKey, err := parseRSAPrivateKey(secret)
		if err != nil {
			return "", fmt.Errorf("failed to parse RSA private key: %v", err)
		}

		// Create hash of the message
		hasher := sha512.New()
		hasher.Write([]byte(headerBase64 + "." + payloadBase64))
		hashed := hasher.Sum(nil)

		// Sign the hash
		signatureBytes, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA512, hashed)
		if err != nil {
			return "", fmt.Errorf("failed to sign with RSA: %v", err)
		}

		signature = base64.RawURLEncoding.EncodeToString(signatureBytes)
	case AlgES256:
		privateKey, err := parseECDSAPrivateKey(secret)
		if err != nil {
			return "", fmt.Errorf("failed to parse ECDSA private key: %v", err)
		}

		// Create hash of the message
		hasher := sha256.New()
		hasher.Write([]byte(headerBase64 + "." + payloadBase64))
		hashed := hasher.Sum(nil)

		// Sign the hash
		r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed)
		if err != nil {
			return "", fmt.Errorf("failed to sign with ECDSA: %v", err)
		}

		// Encode r and s as DER-encoded ASN.1 integers
		signatureBytes := encodeECDSASignature(r, s)
		signature = base64.RawURLEncoding.EncodeToString(signatureBytes)
	case AlgES384:
		privateKey, err := parseECDSAPrivateKey(secret)
		if err != nil {
			return "", fmt.Errorf("failed to parse ECDSA private key: %v", err)
		}

		// Create hash of the message
		hasher := sha512.New384()
		hasher.Write([]byte(headerBase64 + "." + payloadBase64))
		hashed := hasher.Sum(nil)

		// Sign the hash
		r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed)
		if err != nil {
			return "", fmt.Errorf("failed to sign with ECDSA: %v", err)
		}

		// Encode r and s as DER-encoded ASN.1 integers
		signatureBytes := encodeECDSASignature(r, s)
		signature = base64.RawURLEncoding.EncodeToString(signatureBytes)
	case AlgES512:
		privateKey, err := parseECDSAPrivateKey(secret)
		if err != nil {
			return "", fmt.Errorf("failed to parse ECDSA private key: %v", err)
		}

		// Create hash of the message
		hasher := sha512.New()
		hasher.Write([]byte(headerBase64 + "." + payloadBase64))
		hashed := hasher.Sum(nil)

		// Sign the hash
		r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed)
		if err != nil {
			return "", fmt.Errorf("failed to sign with ECDSA: %v", err)
		}

		// Encode r and s as DER-encoded ASN.1 integers
		signatureBytes := encodeECDSASignature(r, s)
		signature = base64.RawURLEncoding.EncodeToString(signatureBytes)
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", headerX.Algorithm)
	}

	return fmt.Sprintf("%s.%s.%s", headerBase64, payloadBase64, signature), nil
}
