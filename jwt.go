package jwt

import (
	"time"

	typ "github.com/go-zoox/core-utils/type"
)

// Options is the options for jwt
type Options struct {
	// Issuer is the people or entity who issued the token.
	Issuer string `json:"iss"`

	// Subject is the subject of the token.
	Subject string `json:"sub"`

	// Audience is the people or entity who used the token.
	Audience string `json:"aud"`

	// ExpiresAt is the time when the token expires.
	ExpiresAt int64 `json:"exp"`

	// NotBefore is the time when the token was valid.
	NotBefore int64 `json:"nbf"`

	// IssuedAt is the time when the token was issued.
	IssuedAt int64 `json:"iat"`

	// JwtID is the unique token identifier.
	JwtID string `json:"jti"`

	// Algorithm is the jwt crypto algorithm.
	Algorithm string `json:"alg"`

	// MaxAge is the token max age, default 2h
	MaxAge time.Duration
}

// Jwt is the jwt
type Jwt interface {
	Sign(payload map[string]interface{}) (string, error)
	Verify(token string) (*typ.Value, error)
	//
	Get(key string) *typ.Value
	// Set(key string, value interface{})
	// Getter & Setter
	SetIssuer(iss string) *jwt
	GetIssuer() string
	SetSubject(sub string) *jwt
	GetSubject() string
	SetAudience(aud string) *jwt
	GetAudience() string
	SetNotBefore(nbf int64) *jwt
	GetNotBefore() int64
	SetExpiresAt(exp int64) *jwt
	GetExpiresAt() int64
	SetIssuedAt(iat int64) *jwt
	GetIssuedAt() int64
	SetJwtID(jti string) *jwt
	GetJwtID() string
	SetAlgorithm(alg string) *jwt
	GetAlgorithm() string
}

type jwt struct {
	secret  string
	options *Options
	//
	header  *Header
	payload *typ.Value
}

// New creates a new JWT
func New(secret string, options ...*Options) Jwt {
	opt := &Options{}
	if len(options) > 0 && options[0] != nil {
		opt = options[0]
	}

	return &jwt{
		secret:  secret,
		options: opt,
	}
}

// Sign signs data with secret
func (j *jwt) Sign(payload map[string]interface{}) (string, error) {
	return Sign(j.secret, payload, &SignOptions{
		Issuer:    j.options.Issuer,
		Subject:   j.options.Subject,
		Audience:  j.options.Audience,
		ExpiresAt: j.options.ExpiresAt,
		NotBefore: j.options.NotBefore,
		IssuedAt:  j.options.IssuedAt,
		JWTID:     j.options.JwtID,
		Algorithm: j.options.Algorithm,
		MaxAge:    j.options.MaxAge,
	})
}

// Verify verifies data with secret
func (j *jwt) Verify(token string) (*typ.Value, error) {
	header, payload, err := Verify(j.secret, token, &VerifyOptions{
		Issuer:    j.options.Issuer,
		Subject:   j.options.Subject,
		Audience:  j.options.Audience,
		ExpiresAt: j.options.ExpiresAt,
		NotBefore: j.options.NotBefore,
		IssuedAt:  j.options.IssuedAt,
		JWTID:     j.options.JwtID,
	})
	if err != nil {
		return nil, err
	}

	j.header = header
	j.payload = payload

	return j.payload, nil
}

// Get ...
func (j *jwt) Get(key string) *typ.Value {
	return j.payload.Get(key)
}

// // Set ...
// func (j *jwt) Set(key string) *typ.Value {
// 	return j.payload.Get(key)
// }

// SetIssuer sets issuer
func (j *jwt) SetIssuer(iss string) *jwt {
	j.options.Issuer = iss
	return j
}

// GetIssuer ...
func (j *jwt) GetIssuer() string {
	return j.payload.Get("iss").String()
}

// SetSubject sets subject
func (j *jwt) SetSubject(sub string) *jwt {
	j.options.Subject = sub
	return j
}

// GetSubject ...
func (j *jwt) GetSubject() string {
	return j.payload.Get("sub").String()
}

// SetAudience sets audience
func (j *jwt) SetAudience(aud string) *jwt {
	j.options.Audience = aud
	return j
}

// GetAudience ...
func (j *jwt) GetAudience() string {
	return j.payload.Get("aud").String()
}

// SetNotBefore sets not before
func (j *jwt) SetNotBefore(nbf int64) *jwt {
	j.options.NotBefore = nbf
	return j
}

// GetNotBefore ...
func (j *jwt) GetNotBefore() int64 {
	return j.payload.Get("nbf").Int64()
}

// SetExpiresAt sets expires at
func (j *jwt) SetExpiresAt(exp int64) *jwt {
	j.options.ExpiresAt = exp
	return j
}

// GetExpiresAt ...
func (j *jwt) GetExpiresAt() int64 {
	return j.payload.Get("exp").Int64()
}

// SetIssuedAt sets issued at
func (j *jwt) SetIssuedAt(iat int64) *jwt {
	j.options.IssuedAt = iat
	return j
}

// GetIssuedAt ...
func (j *jwt) GetIssuedAt() int64 {
	return j.payload.Get("iat").Int64()
}

// SetJwtID sets jwt id
func (j *jwt) SetJwtID(jti string) *jwt {
	j.options.JwtID = jti
	return j
}

func (j *jwt) GetJwtID() string {
	return j.payload.Get("jti").String()
}

// SetAlgorithm sets algorithm
func (j *jwt) SetAlgorithm(alg string) *jwt {
	j.options.Algorithm = alg
	return j
}

// GetAlgorithm ...
func (j *jwt) GetAlgorithm() string {
	return j.header.Algorithm
}
