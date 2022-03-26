package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

// Header contains important information for encrypting / decrypting JWT.
type Header struct {
	// The type of the token.
	// By default, this is "JWT"
	Type string `json:"typ,omitempty"`
	// The algorithm used to sign the token.
	// By default, this is "HS256"
	Algorithm string `json:"alg,omitempty"`
	// Content Type of the token.
	// By default, this is "application/json"
	// ContentType string `json:"cty,omitempty"`
}

func NewHeader(algorithm string) *Header {
	return &Header{
		Type:      "JWT",
		Algorithm: algorithm,
	}
}

// Encode returns an encoded JWT token header
func (h *Header) Encode() (string, error) {
	jsonData, err := json.Marshal(h)
	if err != nil {
		return "", errors.New("unable to marshal header:" + err.Error())
	}
	b64Data := base64.RawURLEncoding.EncodeToString(jsonData)

	return b64Data, nil
}

// Decode decodes the JWT token header
func (h *Header) Decode(encoded string) error {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, h)
	if err != nil {
		return errors.New("unable to unmarshal header:" + err.Error())
	}

	return nil
}
