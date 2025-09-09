package jwt

import (
	"testing"

	"github.com/go-zoox/testify"
)

func TestVerify(t *testing.T) {
	secret := "secret"
	token := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdmF0YXIiOiJodHRwczovL2F2YXRhcnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3UvNzQ2MzY4Nz92PTQiLCJleHAiOjI3NTc0MTE2OTcsImlhdCI6MTY2MzIxODU3OCwiaWQiOjEsImlzcyI6ImdvLXpvb3giLCJuaWNrbmFtZSI6Ilplcm8ifQ.gpkpFw3rPMZFiGoyiz2MUpCNiCQKyYYzhtgkLeo1h-c"

	_, payload, err := Verify(secret, token)
	if err != nil {
		t.Fatal(err)
	}

	testify.Equal(t, payload.Get("id").Float64(), 1)
	testify.Equal(t, payload.Get("nickname").String(), "Zero")
	testify.Equal(t, payload.Get("avatar").String(), "https://avatars.githubusercontent.com/u/7463687?v=4")
}
