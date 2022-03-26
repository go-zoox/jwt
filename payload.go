package jwt

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/go-zoox/jwt/utils"
	"github.com/pkg/errors"
)

type Payload struct {
	// The time when the token was issued.
	IssuedAt int64 `json:"iat,omitempty"`
	// The time when the token expires.
	ExpiresAt int64 `json:"exp,omitempty"`
	// The time when the token was valid.
	NotBefore int64 `json:"nbf,omitempty"`
	// The people or entity who issued the token.
	Issuer string `json:"iss,omitempty"`
	// The people or entity who used the token
	Audience string `json:"aud,omitempty"`
	// The subject of the token
	Subject string `json:"sub,omitempty"`
	// The unique token identifier
	JwtID string `json:"jti,omitempty"`
	// Custom claims
	custom utils.Map
}

// New Claim return a new map representing the claims with the default values. The schema is detailed below.
// 	claim["iss"] Issuer 		- string 	- identifies principal the issued the JWT;
//  claim["sub"] Subject  	- string 	- identifies the subject of the JWT;
//  claim["aud"] Audience 	- string 	- The "aud" (audience) claim identifies the recipients that the JWT is intended for;
//  claim["exp"] Expiration - time		- The "exp" (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing;
//  claim["nbf"] Not before - time 		- Similarly, the not-before time claim identifies the time on which the JWT will start to be accepted for processing;
//  claim["iat"] Issued at  - time    - The "iat" (issued at) claim identifies the time at which the JWT was issued;
//  claim["jti"] JWT ID     - string  - case sensitive unique identifier of the token even among different issuers;
func NewPayload() *Payload {
	return &Payload{
		custom: make(utils.Map),
	}
}

// Set sets the claim in string form.
func (p *Payload) Set(key string, value interface{}) {
	p.custom.Set(key, value)
}

// Get returns the claim in string form and returns an error if the specified claim doesnot exist.
func (p *Payload) Get(key string) *utils.MapValue {
	return p.custom.Get(key)
}

// HasClaim returns if the claims map has the specified key.
func (p *Payload) Has(key string) bool {
	_, ok := p.custom[key]
	return ok
}

// Encode returns an encoded JWT token payload
func (p *Payload) Encode() (string, error) {
	issuedAt := p.IssuedAt
	if issuedAt == 0 {
		issuedAt = time.Now().Unix()
	}

	data := utils.Map{
		"iat": issuedAt,
		"exp": p.ExpiresAt,
		"nbf": p.NotBefore,
		"iss": p.Issuer,
		"aud": p.Audience,
		"sub": p.Subject,
		"jti": p.JwtID,
	}
	p.custom.CopyTo(data)

	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", errors.New("unable to marshal payload:" + err.Error())
	}
	base64Data := base64.RawURLEncoding.EncodeToString([]byte(jsonData))

	return base64Data, nil
}

// Decode decodes the JWT token payload
func (p *Payload) Decode(encoded string) error {
	data := make(utils.Map)

	jsonData, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}

	err = json.Unmarshal(jsonData, &data)
	if err != nil {
		return errors.New("unable to unmarshal payload:" + err.Error())
	}

	p.IssuedAt = data.Get("iat").Int64()
	p.ExpiresAt = data.Get("exp").Int64()
	p.NotBefore = data.Get("nbf").Int64()
	p.Issuer = data.Get("iss").String()
	p.Audience = data.Get("aud").String()
	p.Subject = data.Get("sub").String()
	p.JwtID = data.Get("jti").String()
	p.custom = data

	return nil
}
