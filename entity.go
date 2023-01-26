package jwt

// Header is the header of JWT
type Header struct {
	// The type of the token.
	// By default, this is "JWT"
	Type string `json:"typ"`

	// The algorithm used to sign the token.
	// By default, this is "HS256"
	// Available: HS256 | HS512 | HS384
	Algorithm string `json:"alg"`

	// Content Type of the token.
	// By default, this is "application/json"
	// ContentType string `json:"cty,omitempty"`
}

// Payload is the payload of JWT
type Payload struct {
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
}
