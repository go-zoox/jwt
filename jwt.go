package jwt

import (
	"encoding/base64"
	"strings"
	"time"

	"github.com/go-zoox/jwt/utils"
	"github.com/pkg/errors"
)

// Jwt contains the header and payload of the JWT.
type Jwt struct {
	header  *Header
	payload *Payload
	//
	algorithm *Algorithm
}

func New(secret string, createHash func(secret string) *Algorithm) *Jwt {
	algorithm := createHash(secret)
	header := NewHeader(algorithm.Name)
	payload := NewPayload()

	return &Jwt{
		header:    header,
		payload:   payload,
		algorithm: algorithm,
	}
}

func (j *Jwt) Sign() (string, error) {
	header, err := j.header.Encode()
	if err != nil {
		return "", errors.Wrap(err, "unable to encode header")
	}

	payload, err := j.payload.Encode()
	if err != nil {
		return "", errors.Wrap(err, "unable to encode payload")
	}

	signatureBytes, err := j.algorithm.Sign([]byte(header + "." + payload))
	if err != nil {
		return "", errors.Wrap(err, "unable to sign")
	}

	signature := base64.RawURLEncoding.EncodeToString(signatureBytes)
	return header + "." + payload + "." + signature, nil
}

func (j *Jwt) Verify(token string) error {
	components := strings.Split(token, ".")
	header, payload, signature := components[0], components[1], components[2]

	text := header + "." + payload
	ok, err := j.algorithm.Verify([]byte(text), []byte(signature))
	if !ok {
		return errors.Wrap(err, "unable to sign token")
	}

	if err := j.header.Decode(header); err != nil {
		return errors.Wrap(err, "invalid token, unable to decode header")
	}

	if err := j.payload.Decode(payload); err != nil {
		return errors.Wrap(err, "invalid token, unable to decode payload")
	}

	if j.payload.IssuedAt == 0 {
		return errors.New("invalid token, issued at missing")
	}

	if expiresAt := j.payload.ExpiresAt; expiresAt > 0 && expiresAt < time.Now().Unix() {
		return errors.New("token expired")
	}

	return nil
}

//
func (j *Jwt) Set(key string, value interface{}) {
	j.payload.Set(key, value)
}

func (j *Jwt) Get(key string) *utils.MapValue {
	return j.payload.Get(key)
}

func (j *Jwt) Has(key string) bool {
	return j.payload.Has(key)
}

//
func (j *Jwt) GetIssuedAt() int64 {
	return j.payload.IssuedAt
}

func (j *Jwt) SetIssuedAt(t int64) {
	j.payload.IssuedAt = t
}

func (j *Jwt) GetExpiresAt() int64 {
	return j.payload.ExpiresAt
}

func (j *Jwt) SetExpiresAt(t int64) {
	j.payload.ExpiresAt = t
}

func (j *Jwt) GetNotBefore() int64 {
	return j.payload.NotBefore
}

func (j *Jwt) SetNotBefore(t int64) {
	j.payload.NotBefore = t
}

func (j *Jwt) GetIssuer() string {
	return j.payload.Issuer
}

func (j *Jwt) SetIssuer(s string) {
	j.payload.Issuer = s
}

func (j *Jwt) GetAudience() string {
	return j.payload.Audience
}

func (j *Jwt) SetAudience(s string) {
	j.payload.Audience = s
}

func (j *Jwt) GetSubject() string {
	return j.payload.Subject
}

func (j *Jwt) SetSubject(s string) {
	j.payload.Subject = s
}

func (j *Jwt) GetJwtID() string {
	return j.payload.JwtID
}

func (j *Jwt) SetJwtID(s string) {
	j.payload.JwtID = s
}
