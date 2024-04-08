package jwt

import (
	"errors"
	"fmt"
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
	switch headerX.Algorithm {
	case AlgHS256:
		signature = hmac.Sha256(secret, fmt.Sprintf("%s.%s", headerBase64, payloadBase64), "base64")
	case AlgHS384:
		signature = hmac.Sha384(secret, fmt.Sprintf("%s.%s", headerBase64, payloadBase64), "base64")
	case AlgHS512:
		signature = hmac.Sha512(secret, fmt.Sprintf("%s.%s", headerBase64, payloadBase64), "base64")
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %s", headerX.Algorithm)
	}

	if signature != signatureX {
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
