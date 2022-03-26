package jwt

func NewHS256(secret string) *Jwt {
	return New(secret, HmacSha256)
}

func NewHS512(secret string) *Jwt {
	return New(secret, HmacSha512)
}

func NewHS384(secret string) *Jwt {
	return New(secret, HmacSha384)
}
