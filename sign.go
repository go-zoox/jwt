package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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
}

// Sign signs data with secret
func Sign(secret string, payload map[string]any, options ...*SignOptions) (string, error) {
	var opt *SignOptions = nil
	if len(options) > 0 && options[0] != nil {
		opt = options[0]
	}

	headerX := Header{
		Type:      "JWT",
		Algorithm: AlgHS256,
	}

	now := time.Now().Unix()
	// issuedAt default now
	issuedAt := now
	// expiredAt default 2 hour
	expiredAt := now + 7200

	payloadX := map[string]interface{}{
		"iss": "go-zoox",
		"iat": issuedAt,
		"exp": expiredAt,
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

		if opt.ExpiresAt > 0 {
			payloadX["exp"] = opt.ExpiresAt
		}

		if opt.NotBefore > 0 {
			payloadX["nbf"] = opt.NotBefore
		}

		if opt.IssuedAt > 0 {
			payloadX["iat"] = opt.IssuedAt
		} else {
			payloadX["iat"] = time.Now().Unix()
		}

		if opt.JWTID != "" {
			payloadX["jti"] = opt.JWTID
		}
	}

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
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", headerX.Algorithm)
	}

	return fmt.Sprintf("%s.%s.%s", headerBase64, payloadBase64, signature), nil
}
