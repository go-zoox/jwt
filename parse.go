package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	typ "github.com/go-zoox/core-utils/type"
)

// Parse parses header and payload from token
func Parse(token string) (header *Header, payload *typ.Value, headerRaw, payloadRaw, signatureRaw string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, "", "", "", errors.New("invalid token")
	}

	headerBase64, payloadBase64, signatureX := parts[0], parts[1], parts[2]

	headerDecoded, err := base64.RawURLEncoding.DecodeString(headerBase64)
	if err != nil {
		return nil, nil, "", "", "", err
	}

	payloadDecoded, err := base64.RawURLEncoding.DecodeString(payloadBase64)
	if err != nil {
		return nil, nil, "", "", "", err
	}

	headerX := Header{}
	err = json.Unmarshal(headerDecoded, &headerX)
	if err != nil {
		return nil, nil, "", "", "", err
	}

	payloadX := map[string]interface{}{}
	err = json.Unmarshal(payloadDecoded, &payloadX)
	if err != nil {
		return nil, nil, "", "", "", err
	}

	return &headerX, typ.NewValue(payloadX), headerBase64, payloadBase64, signatureX, nil
}
