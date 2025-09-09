package jwt

import (
	"testing"

	"github.com/go-zoox/testify"
)

func TestIs(t *testing.T) {
	testify.Equal(t, Is(""), false, "empty string is not a jwt token")
	testify.Equal(t, Is("abc"), false, "abc is not a jwt token")
	testify.Equal(t, Is("abc.def"), false, "abc.def is not a jwt token")
	testify.Equal(t, Is("abc.def.ghi"), false, "abc.def.ghi is not a jwt token")
	testify.Equal(t, Is("abc.def.ghi.jkl"), false, "abc.def.ghi.jkl is not a jwt token")
	testify.Equal(t, Is("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdmF0YXIiOiJodHRwczovL2F2YXRhcnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3UvNzQ2MzY4Nz92PTQiLCJleHAiOjI3MTI1NDEyMDcsImlhdCI6MTY2MzIxODU3OCwiaWQiOjEsImlzcyI6ImdvLXpvb3giLCJuaWNrbmFtZSI6Ilplcm8ifQ.oO3EckRx1yMkBNyQzCWF23Q_eU7JTlmyKdzHylmgI_k"), true, "valid jwt token")
}
