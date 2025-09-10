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

func NewRS256(privateKey string) Jwt {
	return New(privateKey, &Options{
		Algorithm: AlgRS256,
	})
}

func NewRS512(privateKey string) Jwt {
	return New(privateKey, &Options{
		Algorithm: AlgRS512,
	})
}

func NewRS384(privateKey string) Jwt {
	return New(privateKey, &Options{
		Algorithm: AlgRS384,
	})
}

func NewES256(privateKey string) Jwt {
	return New(privateKey, &Options{
		Algorithm: AlgES256,
	})
}

func NewES384(privateKey string) Jwt {
	return New(privateKey, &Options{
		Algorithm: AlgES384,
	})
}

func NewES512(privateKey string) Jwt {
	return New(privateKey, &Options{
		Algorithm: AlgES512,
	})
}

func NewPS256(privateKey string) Jwt {
	return New(privateKey, &Options{
		Algorithm: AlgPS256,
	})
}

func NewPS384(privateKey string) Jwt {
	return New(privateKey, &Options{
		Algorithm: AlgPS384,
	})
}

func NewPS512(privateKey string) Jwt {
	return New(privateKey, &Options{
		Algorithm: AlgPS512,
	})
}
