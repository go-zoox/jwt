package jwt

import (
	"testing"

	"github.com/go-zoox/testify"
)

func TestJWT(t *testing.T) {
	j := New("secret", &Options{
		IssuedAt: 1663218578,
	})

	token, err := j.Sign(map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
		"avatar":   "https://avatars.githubusercontent.com/u/7463687?v=4",
	})
	if err != nil {
		t.Fatal(err)
	}

	testify.Equal(t, "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdmF0YXIiOiJodHRwczovL2F2YXRhcnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3UvNzQ2MzY4Nz92PTQiLCJpYXQiOjE2NjMyMTg1NzgsImlkIjoxLCJpc3MiOiJnby16b294Iiwibmlja25hbWUiOiJaZXJvIn0.fcJD66GgF-k2JgfuKgKW5PvqMEOhXqMQbJyMRrIdbfs", token)

	payload, err := j.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	if j.GetIssuedAt() == 0 {
		t.Fatal("issuedAt mismatch")
	}

	if j.GetExpiresAt() != 0 {
		t.Fatal("expiresAt mismatch")
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
		IssuedAt: 1648268173,
	})
	payload := map[string]interface{}{
		"name": "zero",
		"id":   "abcd",
	}

	_token := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NDgyNjgxNzMsImlkIjoiYWJjZCIsImlzcyI6ImdvLXpvb3giLCJuYW1lIjoiemVybyJ9.6InYxP1hzY-FZHzo8-ehJX_sbWi1qCF_VLoajoTj7do"

	token, err := jwt.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	if token != _token {
		t.Fatalf("expect: %s, but %s", token, _token)
	}
}
