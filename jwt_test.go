package jwt

import (
	"testing"
)

func TestJWTSign(t *testing.T) {
	secret := "secret"
	jwt := NewHS256(secret)
	jwt.SetIssuedAt(1648268173)
	jwt.Set("name", "zero")
	jwt.Set("id", "abcd")

	_token := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiIiLCJleHAiOjAsImlhdCI6MTY0ODI2ODE3MywiaWQiOiJhYmNkIiwiaXNzIjoiIiwianRpIjoiIiwibmFtZSI6Inplcm8iLCJuYmYiOjAsInN1YiI6IiJ9.QSV-slPLFCZECmID-fRzEyZXFpP8WHqUhIt-6vmth7g"

	token, err := jwt.Sign()
	if err != nil {
		t.Fatal(err)
	}

	if token != _token {
		t.Fatalf("expect: %s, but %s", token, _token)
	}
}

func TestJWTVerify(t *testing.T) {
	token := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiIiLCJleHAiOjAsImlhdCI6MTY0ODI2ODE3MywiaWQiOiJhYmNkIiwiaXNzIjoiIiwianRpIjoiIiwibmFtZSI6Inplcm8iLCJuYmYiOjAsInN1YiI6IiJ9.QSV-slPLFCZECmID-fRzEyZXFpP8WHqUhIt-6vmth7g"
	secret := "secret"
	jwt := NewHS256(secret)

	if err := jwt.Verify(token); err != nil {
		t.Fatal(err)
	}

	if jwt.Get("name").String() != "zero" {
		t.Fatal("name mismatch")
	}

	if jwt.Get("id").String() != "abcd" {
		t.Fatal("id mismatch")
	}

	if jwt.GetIssuedAt() == 0 {
		t.Fatal("issuedAt mismatch")
	}

	if jwt.GetExpiresAt() != 0 {
		t.Fatal("expiresAt mismatch")
	}

	if jwt.GetNotBefore() != 0 {
		t.Fatal("notBefore mismatch")
	}

	if jwt.GetIssuer() != "" {
		t.Fatal("issuer mismatch")
	}

	if jwt.GetAudience() != "" {
		t.Fatal("audience mismatch")
	}

	if jwt.GetSubject() != "" {
		t.Fatal("subject mismatch")
	}

	if jwt.GetJwtID() != "" {
		t.Fatal("jwtID mismatch")
	}
}

func TestJWTVerify2(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NDgyNjkyNzZ9.H_MAA3Xau6z3-4VWOUk8ojGiaV2gCfVyqRUdhS8d0xE"
	secret := "secret"
	jwt := NewHS256(secret)

	if err := jwt.Verify(token); err != nil {
		t.Fatal(err)
	}

	if jwt.GetIssuedAt() == 0 {
		t.Fatal("issuedAt mismatch")
	}

	if jwt.GetExpiresAt() != 0 {
		t.Fatal("expiresAt mismatch")
	}

	if jwt.GetNotBefore() != 0 {
		t.Fatal("notBefore mismatch")
	}

	if jwt.GetIssuer() != "" {
		t.Fatal("issuer mismatch")
	}

	if jwt.GetAudience() != "" {
		t.Fatal("audience mismatch")
	}

	if jwt.GetSubject() != "" {
		t.Fatal("subject mismatch")
	}

	if jwt.GetJwtID() != "" {
		t.Fatal("jwtID mismatch")
	}

	if jwt.GetIssuedAt() != 1648269276 {
		t.Fatal("issuedAt mismatch")
	}
}
