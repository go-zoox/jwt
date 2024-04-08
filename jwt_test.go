package jwt

import (
	"testing"

	"github.com/go-zoox/testify"
)

func TestJWT(t *testing.T) {
	j := New("secret", &Options{
		IssuedAt:  1663218578,
		ExpiresAt: 2663225778,
	})

	token, err := j.Sign(map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
		"avatar":   "https://avatars.githubusercontent.com/u/7463687?v=4",
	})
	if err != nil {
		t.Fatal(err)
	}

	testify.Equal(t, "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdmF0YXIiOiJodHRwczovL2F2YXRhcnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3UvNzQ2MzY4Nz92PTQiLCJleHAiOjI2NjMyMjU3NzgsImlhdCI6MTY2MzIxODU3OCwiaWQiOjEsImlzcyI6ImdvLXpvb3giLCJuaWNrbmFtZSI6Ilplcm8ifQ.-5GEqebxP2ax6ZLM0St4rArMFnE56e6vITK9vexpYlU", token)

	payload, err := j.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	if j.GetIssuedAt() == 0 {
		t.Fatal("issuedAt mismatch")
	}

	if j.GetExpiresAt() != 2663225778 {
		t.Fatalf("expiresAt mismatch, got %d", j.GetExpiresAt())
	}

	if j.GetNotBefore() != 0 {
		t.Fatal("notBefore mismatch")
	}

	if j.GetIssuer() != "go-zoox" {
		t.Fatal("issuer mismatch")
	}

	if j.GetAudience() != "" {
		t.Fatal("audience mismatch")
	}

	if j.GetSubject() != "" {
		t.Fatal("subject mismatch")
	}

	if j.GetJwtID() != "" {
		t.Fatal("jwtID mismatch")
	}

	testify.Equal(t, payload.Get("id").Float64(), 1)
	testify.Equal(t, payload.Get("nickname").String(), "Zero")
	testify.Equal(t, payload.Get("avatar").String(), "https://avatars.githubusercontent.com/u/7463687?v=4")
}

func TestGoZooxJWTSign(t *testing.T) {
	secret := "secret"
	jwt := New(secret, &Options{
		IssuedAt:  1648268173,
		ExpiresAt: 1712541092,
	})
	payload := map[string]interface{}{
		"name": "zero",
		"id":   "abcd",
	}

	_token := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MTI1NDEwOTIsImlhdCI6MTY0ODI2ODE3MywiaWQiOiJhYmNkIiwiaXNzIjoiZ28tem9veCIsIm5hbWUiOiJ6ZXJvIn0.h_oS3wSWLf2BqGoBNysVFWR9xWfsDVXHKSiK5sv_zPg"

	token, err := jwt.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	if token != _token {
		t.Fatalf("expect: %s, but %s", token, _token)
	}
}
