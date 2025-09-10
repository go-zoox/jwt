package jwt

import (
	"time"
)

// JWTBuilder provides a fluent interface for building JWT instances
type JWTBuilder struct {
	jwt *jwt
}

// NewBuilder creates a new JWT builder
func NewBuilder() *JWTBuilder {
	return &JWTBuilder{
		jwt: &jwt{
			secret:  "",
			options: &Options{},
			header:  nil,
			payload: nil,
		},
	}
}

// WithSecret sets the secret key
func (b *JWTBuilder) WithSecret(secret string) *JWTBuilder {
	b.jwt.secret = secret
	return b
}

// WithAlgorithm sets the algorithm
func (b *JWTBuilder) WithAlgorithm(algorithm string) *JWTBuilder {
	b.jwt.options.Algorithm = algorithm
	return b
}

// WithIssuer sets the issuer
func (b *JWTBuilder) WithIssuer(issuer string) *JWTBuilder {
	b.jwt.options.Issuer = issuer
	return b
}

// WithSubject sets the subject
func (b *JWTBuilder) WithSubject(subject string) *JWTBuilder {
	b.jwt.options.Subject = subject
	return b
}

// WithAudience sets the audience
func (b *JWTBuilder) WithAudience(audience string) *JWTBuilder {
	b.jwt.options.Audience = audience
	return b
}

// WithExpiresAt sets the expiration time
func (b *JWTBuilder) WithExpiresAt(expiresAt int64) *JWTBuilder {
	b.jwt.options.ExpiresAt = expiresAt
	return b
}

// WithExpiresIn sets the expiration time relative to now
func (b *JWTBuilder) WithExpiresIn(duration time.Duration) *JWTBuilder {
	b.jwt.options.ExpiresAt = time.Now().Add(duration).Unix()
	return b
}

// WithNotBefore sets the not before time
func (b *JWTBuilder) WithNotBefore(notBefore int64) *JWTBuilder {
	b.jwt.options.NotBefore = notBefore
	return b
}

// WithIssuedAt sets the issued at time
func (b *JWTBuilder) WithIssuedAt(issuedAt int64) *JWTBuilder {
	b.jwt.options.IssuedAt = issuedAt
	return b
}

// WithIssuedNow sets the issued at time to now
func (b *JWTBuilder) WithIssuedNow() *JWTBuilder {
	b.jwt.options.IssuedAt = time.Now().Unix()
	return b
}

// WithJWTID sets the JWT ID
func (b *JWTBuilder) WithJWTID(jwtID string) *JWTBuilder {
	b.jwt.options.JwtID = jwtID
	return b
}

// WithMaxAge sets the maximum age
func (b *JWTBuilder) WithMaxAge(maxAge time.Duration) *JWTBuilder {
	b.jwt.options.MaxAge = maxAge
	return b
}

// WithOptions sets multiple options at once
func (b *JWTBuilder) WithOptions(options *Options) *JWTBuilder {
	if options != nil {
		b.jwt.options = options
	}
	return b
}

// Build constructs the final JWT instance
func (b *JWTBuilder) Build() Jwt {
	return b.jwt
}

// BuildAndSign creates a JWT instance and signs it with the given payload
func (b *JWTBuilder) BuildAndSign(payload map[string]interface{}) (string, error) {
	jwtInstance := b.Build()
	return jwtInstance.Sign(payload)
}

// Convenience methods for common algorithms

// BuildHS256 creates a JWT builder configured for HS256
func BuildHS256(secret string) *JWTBuilder {
	return NewBuilder().
		WithSecret(secret).
		WithAlgorithm(AlgHS256)
}

// BuildHS384 creates a JWT builder configured for HS384
func BuildHS384(secret string) *JWTBuilder {
	return NewBuilder().
		WithSecret(secret).
		WithAlgorithm(AlgHS384)
}

// BuildHS512 creates a JWT builder configured for HS512
func BuildHS512(secret string) *JWTBuilder {
	return NewBuilder().
		WithSecret(secret).
		WithAlgorithm(AlgHS512)
}

// BuildRS256 creates a JWT builder configured for RS256
func BuildRS256(privateKey string) *JWTBuilder {
	return NewBuilder().
		WithSecret(privateKey).
		WithAlgorithm(AlgRS256)
}

// BuildRS384 creates a JWT builder configured for RS384
func BuildRS384(privateKey string) *JWTBuilder {
	return NewBuilder().
		WithSecret(privateKey).
		WithAlgorithm(AlgRS384)
}

// BuildRS512 creates a JWT builder configured for RS512
func BuildRS512(privateKey string) *JWTBuilder {
	return NewBuilder().
		WithSecret(privateKey).
		WithAlgorithm(AlgRS512)
}

// BuildES256 creates a JWT builder configured for ES256
func BuildES256(privateKey string) *JWTBuilder {
	return NewBuilder().
		WithSecret(privateKey).
		WithAlgorithm(AlgES256)
}

// BuildES384 creates a JWT builder configured for ES384
func BuildES384(privateKey string) *JWTBuilder {
	return NewBuilder().
		WithSecret(privateKey).
		WithAlgorithm(AlgES384)
}

// BuildES512 creates a JWT builder configured for ES512
func BuildES512(privateKey string) *JWTBuilder {
	return NewBuilder().
		WithSecret(privateKey).
		WithAlgorithm(AlgES512)
}

// BuildPS256 creates a JWT builder configured for PS256
func BuildPS256(privateKey string) *JWTBuilder {
	return NewBuilder().
		WithSecret(privateKey).
		WithAlgorithm(AlgPS256)
}

// BuildPS384 creates a JWT builder configured for PS384
func BuildPS384(privateKey string) *JWTBuilder {
	return NewBuilder().
		WithSecret(privateKey).
		WithAlgorithm(AlgPS384)
}

// BuildPS512 creates a JWT builder configured for PS512
func BuildPS512(privateKey string) *JWTBuilder {
	return NewBuilder().
		WithSecret(privateKey).
		WithAlgorithm(AlgPS512)
}
