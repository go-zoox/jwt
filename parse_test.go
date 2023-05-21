package jwt

import (
	"testing"

	"github.com/go-zoox/testify"
)

func TestParse(t *testing.T) {
	token := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdmF0YXIiOiJodHRwczovL2F2YXRhcnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3UvNzQ2MzY4Nz92PTQiLCJpYXQiOjE2NjMyMTg1NzgsImlkIjoxLCJpc3MiOiJnby16b294Iiwibmlja25hbWUiOiJaZXJvIn0.fcJD66GgF-k2JgfuKgKW5PvqMEOhXqMQbJyMRrIdbfs"

	header, payload, headerRaw, payloadRaw, signature, err := Parse(token)
	if err != nil {
		t.Fatal(err)
	}

	testify.Equal(t, header.Type, "JWT")
	testify.Equal(t, header.Algorithm, AlgHS256)

	testify.Equal(t, payload.Get("id").Float64(), 1)
	testify.Equal(t, payload.Get("nickname").String(), "Zero")
	testify.Equal(t, payload.Get("avatar").String(), "https://avatars.githubusercontent.com/u/7463687?v=4")

	testify.Equal(t, headerRaw, "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9")
	testify.Equal(t, payloadRaw, "eyJhdmF0YXIiOiJodHRwczovL2F2YXRhcnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3UvNzQ2MzY4Nz92PTQiLCJpYXQiOjE2NjMyMTg1NzgsImlkIjoxLCJpc3MiOiJnby16b294Iiwibmlja25hbWUiOiJaZXJvIn0")
	testify.Equal(t, signature, "fcJD66GgF-k2JgfuKgKW5PvqMEOhXqMQbJyMRrIdbfs")
}
