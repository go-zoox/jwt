package jwt

func Is(token string) (ok bool) {
	header, payload, _, _, signature, err := Parse(token)
	if err != nil {
		return false
	}

	if header == nil || payload == nil || signature == "" {
		return false
	}

	return true
}
