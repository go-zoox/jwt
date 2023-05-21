package jwt

func NewHS256(secret string) Jwt {
	return New(secret, &Options{
		Algorithm: AlgHS256,
	})
}

func NewHS512(secret string) Jwt {
	return New(secret, &Options{
		Algorithm: AlgHS512,
	})
}

func NewHS384(secret string) Jwt {
	return New(secret, &Options{
		Algorithm: AlgHS384,
	})
}
