package jwt

import (
	"testing"

	"github.com/go-zoox/testify"
)

func TestSign(t *testing.T) {
	secret := "secret"
	payload := map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
		"avatar":   "https://avatars.githubusercontent.com/u/7463687?v=4",
	}

	token, err := Sign(secret, payload, &SignOptions{
		IssuedAt: 1663218578,
	})
	if err != nil {
		t.Fatal(err)
	}

	testify.Equal(t, "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdmF0YXIiOiJodHRwczovL2F2YXRhcnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3UvNzQ2MzY4Nz92PTQiLCJleHAiOjE2NjMyMjU3NzgsImlhdCI6MTY2MzIxODU3OCwiaWQiOjEsImlzcyI6ImdvLXpvb3giLCJuaWNrbmFtZSI6Ilplcm8ifQ.FuD9kqJyeGmAev4xoITR3ImCSeisG_oXhZRQhLhjXxU", token)
}
