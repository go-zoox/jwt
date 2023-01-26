package jwt

func NewHS256(secret string) Jwt {
	return New(secret, &Options{
		Algorithm: "HS256",
	})
}

func NewHS512(secret string) Jwt {
	return New(secret, &Options{
		Algorithm: "HS512",
	})
}

func NewHS384(secret string) Jwt {
	return New(secret, &Options{
		Algorithm: "HS384",
	})
}
