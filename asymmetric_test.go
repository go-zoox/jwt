// Package jwt tests for asymmetric JWT algorithms (RSA: RS256, RS384, RS512 | ECDSA: ES256, ES384, ES512 | RSA-PSS: PS256, PS384, PS512)
package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-zoox/testify"
)

// generateTestRSAKeyPair generates a test RSA key pair for testing
func generateTestRSAKeyPair() (privateKeyPEM, publicKeyPEM string, err error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	// Encode private key to PEM
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}

	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	}
	privateKeyPEM = string(pem.EncodeToMemory(privateKeyBlock))

	// Encode public key to PEM
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}
	publicKeyPEM = string(pem.EncodeToMemory(publicKeyBlock))

	return privateKeyPEM, publicKeyPEM, nil
}

// generateTestECDSAKeyPair generates a test ECDSA key pair for testing
func generateTestECDSAKeyPair() (privateKeyPEM, publicKeyPEM string, err error) {
	// Generate private key using P-256 curve
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	// Encode private key to PEM
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}

	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	}
	privateKeyPEM = string(pem.EncodeToMemory(privateKeyBlock))

	// Encode public key to PEM
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}
	publicKeyPEM = string(pem.EncodeToMemory(publicKeyBlock))

	return privateKeyPEM, publicKeyPEM, nil
}

func TestRS256SignAndVerify(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Test signing with RS256
	payload := map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
		"avatar":   "https://avatars.githubusercontent.com/u/7463687?v=4",
	}

	token, err := Sign(privateKeyPEM, payload, &SignOptions{
		Algorithm: AlgRS256,
		IssuedAt:  1663218578,
		ExpiresAt: 2663225778,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Test verification with RS256
	header, payloadResult, err := Verify(publicKeyPEM, token)
	if err != nil {
		t.Fatal(err)
	}

	// Verify algorithm
	testify.Equal(t, AlgRS256, header.Algorithm)

	// Verify payload content
	testify.Equal(t, payloadResult.Get("id").Float64(), 1.0)
	testify.Equal(t, payloadResult.Get("nickname").String(), "Zero")
	testify.Equal(t, payloadResult.Get("avatar").String(), "https://avatars.githubusercontent.com/u/7463687?v=4")
}

func TestRS256JWT(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Create JWT instance with RS256
	j := NewRS256(privateKeyPEM)

	// Set custom options
	j.SetIssuer("test-issuer")
	j.SetSubject("test-subject")
	j.SetAudience("test-audience")
	j.SetIssuedAt(1663218578)
	j.SetExpiresAt(2663225778)

	payload := map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
		"avatar":   "https://avatars.githubusercontent.com/u/7463687?v=4",
	}

	// Sign the token
	token, err := j.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Create a new JWT instance for verification with public key
	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgRS256,
	})

	// Verify the token
	payloadResult, err := jVerify.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	// Verify payload content
	testify.Equal(t, payloadResult.Get("id").Float64(), 1.0)
	testify.Equal(t, payloadResult.Get("nickname").String(), "Zero")
	testify.Equal(t, payloadResult.Get("avatar").String(), "https://avatars.githubusercontent.com/u/7463687?v=4")

	// Verify JWT claims from the verification result
	testify.Equal(t, payloadResult.Get("iss").String(), "test-issuer")
	testify.Equal(t, payloadResult.Get("sub").String(), "test-subject")
	testify.Equal(t, payloadResult.Get("aud").String(), "test-audience")
	testify.Equal(t, payloadResult.Get("iat").Int64(), int64(1663218578))
	testify.Equal(t, payloadResult.Get("exp").Int64(), int64(2663225778))
}

func TestRS256AutoIssuedAtAndExpiredAt(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	j := NewRS256(privateKeyPEM)
	token, err := j.Sign(map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
		"avatar":   "https://avatars.githubusercontent.com/u/7463687?v=4",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a new JWT instance for verification with public key
	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgRS256,
	})

	payload, err := jVerify.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	testify.NotEqual(t, payload.Get("iat").Int64(), 0, "issuedAt is 0")
	testify.NotEqual(t, payload.Get("exp").Int64(), 0, "expiresAt is 0")

	// default expiresAt - issuedAt = 7200
	if payload.Get("exp").Int64()-payload.Get("iat").Int64() != 7200 {
		t.Fatalf("expiresAt - issuedAt != 7200, got %d", payload.Get("exp").Int64()-payload.Get("iat").Int64())
	}

	testify.Equal(t, payload.Get("id").Float64(), 1.0)
	testify.Equal(t, payload.Get("nickname").String(), "Zero")
	testify.Equal(t, payload.Get("avatar").String(), "https://avatars.githubusercontent.com/u/7463687?v=4")
}

func TestRS256InvalidSignature(t *testing.T) {
	privateKeyPEM, _, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Sign with one key pair
	j1 := NewRS256(privateKeyPEM)
	token, err := j1.Sign(map[string]interface{}{
		"id": 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Generate another key pair for verification
	_, wrongPublicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Try to verify with wrong public key
	jVerify := New(wrongPublicKeyPEM, &Options{
		Algorithm: AlgRS256,
	})

	_, err = jVerify.Verify(token)
	if err == nil {
		t.Fatal("Expected verification to fail with wrong public key")
	}

	if !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("Expected error to contain 'invalid signature', got: %s", err.Error())
	}
}

func TestRS256ExpiredToken(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	j := NewRS256(privateKeyPEM)
	j.SetIssuedAt(time.Now().Unix() - 7200)  // 2 hours ago
	j.SetExpiresAt(time.Now().Unix() - 3600) // 1 hour ago (expired)

	token, err := j.Sign(map[string]interface{}{
		"id": 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a new JWT instance for verification with public key
	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgRS256,
	})

	_, err = jVerify.Verify(token)
	if err == nil {
		t.Fatal("Expected verification to fail with expired token")
	}

	if !strings.Contains(err.Error(), "token expired") {
		t.Fatalf("Expected error to contain 'token expired', got: %s", err.Error())
	}
}

func TestRS512SignAndVerify(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Test signing with RS512
	payload := map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
		"avatar":   "https://avatars.githubusercontent.com/u/7463687?v=4",
	}

	token, err := Sign(privateKeyPEM, payload, &SignOptions{
		Algorithm: AlgRS512,
		IssuedAt:  1663218578,
		ExpiresAt: 2663225778,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Test verification with RS512
	header, payloadResult, err := Verify(publicKeyPEM, token)
	if err != nil {
		t.Fatal(err)
	}

	// Verify algorithm
	testify.Equal(t, AlgRS512, header.Algorithm)

	// Verify payload content
	testify.Equal(t, payloadResult.Get("id").Float64(), 1.0)
	testify.Equal(t, payloadResult.Get("nickname").String(), "Zero")
	testify.Equal(t, payloadResult.Get("avatar").String(), "https://avatars.githubusercontent.com/u/7463687?v=4")
}

func TestRS384SignAndVerify(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Test signing with RS384
	payload := map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
		"avatar":   "https://avatars.githubusercontent.com/u/7463687?v=4",
	}

	token, err := Sign(privateKeyPEM, payload, &SignOptions{
		Algorithm: AlgRS384,
		IssuedAt:  1663218578,
		ExpiresAt: 2663225778,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Test verification with RS384
	header, payloadResult, err := Verify(publicKeyPEM, token)
	if err != nil {
		t.Fatal(err)
	}

	// Verify algorithm
	testify.Equal(t, AlgRS384, header.Algorithm)

	// Verify payload content
	testify.Equal(t, payloadResult.Get("id").Float64(), 1.0)
	testify.Equal(t, payloadResult.Get("nickname").String(), "Zero")
	testify.Equal(t, payloadResult.Get("avatar").String(), "https://avatars.githubusercontent.com/u/7463687?v=4")
}

func TestRS512JWT(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Create JWT instance with RS512
	j := NewRS512(privateKeyPEM)

	// Set custom options
	j.SetIssuer("test-issuer")
	j.SetSubject("test-subject")
	j.SetAudience("test-audience")
	j.SetIssuedAt(1663218578)
	j.SetExpiresAt(2663225778)

	payload := map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
		"avatar":   "https://avatars.githubusercontent.com/u/7463687?v=4",
	}

	// Sign the token
	token, err := j.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Create a new JWT instance for verification with public key
	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgRS512,
	})

	// Verify the token
	payloadResult, err := jVerify.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	// Verify payload content
	testify.Equal(t, payloadResult.Get("id").Float64(), 1.0)
	testify.Equal(t, payloadResult.Get("nickname").String(), "Zero")
	testify.Equal(t, payloadResult.Get("avatar").String(), "https://avatars.githubusercontent.com/u/7463687?v=4")

	// Verify JWT claims from the verification result
	testify.Equal(t, payloadResult.Get("iss").String(), "test-issuer")
	testify.Equal(t, payloadResult.Get("sub").String(), "test-subject")
	testify.Equal(t, payloadResult.Get("aud").String(), "test-audience")
	testify.Equal(t, payloadResult.Get("iat").Int64(), int64(1663218578))
	testify.Equal(t, payloadResult.Get("exp").Int64(), int64(2663225778))
}

func TestRS384JWT(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Create JWT instance with RS384
	j := NewRS384(privateKeyPEM)

	// Set custom options
	j.SetIssuer("test-issuer")
	j.SetSubject("test-subject")
	j.SetAudience("test-audience")
	j.SetIssuedAt(1663218578)
	j.SetExpiresAt(2663225778)

	payload := map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
		"avatar":   "https://avatars.githubusercontent.com/u/7463687?v=4",
	}

	// Sign the token
	token, err := j.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Create a new JWT instance for verification with public key
	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgRS384,
	})

	// Verify the token
	payloadResult, err := jVerify.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	// Verify payload content
	testify.Equal(t, payloadResult.Get("id").Float64(), 1.0)
	testify.Equal(t, payloadResult.Get("nickname").String(), "Zero")
	testify.Equal(t, payloadResult.Get("avatar").String(), "https://avatars.githubusercontent.com/u/7463687?v=4")

	// Verify JWT claims from the verification result
	testify.Equal(t, payloadResult.Get("iss").String(), "test-issuer")
	testify.Equal(t, payloadResult.Get("sub").String(), "test-subject")
	testify.Equal(t, payloadResult.Get("aud").String(), "test-audience")
	testify.Equal(t, payloadResult.Get("iat").Int64(), int64(1663218578))
	testify.Equal(t, payloadResult.Get("exp").Int64(), int64(2663225778))
}

func TestRS512InvalidSignature(t *testing.T) {
	privateKeyPEM, _, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Sign with one key pair
	j1 := NewRS512(privateKeyPEM)
	token, err := j1.Sign(map[string]interface{}{
		"id": 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Generate another key pair for verification
	_, wrongPublicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Try to verify with wrong public key
	jVerify := New(wrongPublicKeyPEM, &Options{
		Algorithm: AlgRS512,
	})

	_, err = jVerify.Verify(token)
	if err == nil {
		t.Fatal("Expected verification to fail with wrong public key")
	}

	if !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("Expected error to contain 'invalid signature', got: %s", err.Error())
	}
}

func TestRS384InvalidSignature(t *testing.T) {
	privateKeyPEM, _, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Sign with one key pair
	j1 := NewRS384(privateKeyPEM)
	token, err := j1.Sign(map[string]interface{}{
		"id": 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Generate another key pair for verification
	_, wrongPublicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Try to verify with wrong public key
	jVerify := New(wrongPublicKeyPEM, &Options{
		Algorithm: AlgRS384,
	})

	_, err = jVerify.Verify(token)
	if err == nil {
		t.Fatal("Expected verification to fail with wrong public key")
	}

	if !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("Expected error to contain 'invalid signature', got: %s", err.Error())
	}
}

func TestRS512AutoIssuedAtAndExpiredAt(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	j := NewRS512(privateKeyPEM)
	token, err := j.Sign(map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
		"avatar":   "https://avatars.githubusercontent.com/u/7463687?v=4",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a new JWT instance for verification with public key
	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgRS512,
	})

	payload, err := jVerify.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	testify.NotEqual(t, payload.Get("iat").Int64(), 0, "issuedAt is 0")
	testify.NotEqual(t, payload.Get("exp").Int64(), 0, "expiresAt is 0")

	// default expiresAt - issuedAt = 7200
	if payload.Get("exp").Int64()-payload.Get("iat").Int64() != 7200 {
		t.Fatalf("expiresAt - issuedAt != 7200, got %d", payload.Get("exp").Int64()-payload.Get("iat").Int64())
	}

	testify.Equal(t, payload.Get("id").Float64(), 1.0)
	testify.Equal(t, payload.Get("nickname").String(), "Zero")
	testify.Equal(t, payload.Get("avatar").String(), "https://avatars.githubusercontent.com/u/7463687?v=4")
}

func TestRS384AutoIssuedAtAndExpiredAt(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	j := NewRS384(privateKeyPEM)
	token, err := j.Sign(map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
		"avatar":   "https://avatars.githubusercontent.com/u/7463687?v=4",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a new JWT instance for verification with public key
	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgRS384,
	})

	payload, err := jVerify.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	testify.NotEqual(t, payload.Get("iat").Int64(), 0, "issuedAt is 0")
	testify.NotEqual(t, payload.Get("exp").Int64(), 0, "expiresAt is 0")

	// default expiresAt - issuedAt = 7200
	if payload.Get("exp").Int64()-payload.Get("iat").Int64() != 7200 {
		t.Fatalf("expiresAt - issuedAt != 7200, got %d", payload.Get("exp").Int64()-payload.Get("iat").Int64())
	}

	testify.Equal(t, payload.Get("id").Float64(), 1.0)
	testify.Equal(t, payload.Get("nickname").String(), "Zero")
	testify.Equal(t, payload.Get("avatar").String(), "https://avatars.githubusercontent.com/u/7463687?v=4")
}

func TestRS512ExpiredToken(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	j := NewRS512(privateKeyPEM)
	j.SetIssuedAt(time.Now().Unix() - 7200)  // 2 hours ago
	j.SetExpiresAt(time.Now().Unix() - 3600) // 1 hour ago (expired)

	token, err := j.Sign(map[string]interface{}{
		"id": 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a new JWT instance for verification with public key
	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgRS512,
	})

	_, err = jVerify.Verify(token)
	if err == nil {
		t.Fatal("Expected verification to fail with expired token")
	}

	if !strings.Contains(err.Error(), "token expired") {
		t.Fatalf("Expected error to contain 'token expired', got: %s", err.Error())
	}
}

func TestRS384ExpiredToken(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	j := NewRS384(privateKeyPEM)
	j.SetIssuedAt(time.Now().Unix() - 7200)  // 2 hours ago
	j.SetExpiresAt(time.Now().Unix() - 3600) // 1 hour ago (expired)

	token, err := j.Sign(map[string]interface{}{
		"id": 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a new JWT instance for verification with public key
	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgRS384,
	})

	_, err = jVerify.Verify(token)
	if err == nil {
		t.Fatal("Expected verification to fail with expired token")
	}

	if !strings.Contains(err.Error(), "token expired") {
		t.Fatalf("Expected error to contain 'token expired', got: %s", err.Error())
	}
}

func TestRS512InvalidPrivateKey(t *testing.T) {
	invalidPrivateKey := "invalid-private-key"

	j := NewRS512(invalidPrivateKey)
	_, err := j.Sign(map[string]interface{}{
		"id": 1,
	})
	if err == nil {
		t.Fatal("Expected signing to fail with invalid private key")
	}

	if !strings.Contains(err.Error(), "failed to parse RSA private key") {
		t.Fatalf("Expected error to contain 'failed to parse RSA private key', got: %s", err.Error())
	}
}

func TestRS384InvalidPrivateKey(t *testing.T) {
	invalidPrivateKey := "invalid-private-key"

	j := NewRS384(invalidPrivateKey)
	_, err := j.Sign(map[string]interface{}{
		"id": 1,
	})
	if err == nil {
		t.Fatal("Expected signing to fail with invalid private key")
	}

	if !strings.Contains(err.Error(), "failed to parse RSA private key") {
		t.Fatalf("Expected error to contain 'failed to parse RSA private key', got: %s", err.Error())
	}
}

func TestRS512InvalidPublicKey(t *testing.T) {
	privateKeyPEM, _, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	invalidPublicKey := "invalid-public-key"

	// Sign with valid private key
	j := NewRS512(privateKeyPEM)
	token, err := j.Sign(map[string]interface{}{
		"id": 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Try to verify with invalid public key
	jVerify := New(invalidPublicKey, &Options{
		Algorithm: AlgRS512,
	})

	_, err = jVerify.Verify(token)
	if err == nil {
		t.Fatal("Expected verification to fail with invalid public key")
	}

	if !strings.Contains(err.Error(), "failed to parse RSA public key") {
		t.Fatalf("Expected error to contain 'failed to parse RSA public key', got: %s", err.Error())
	}
}

func TestRS384InvalidPublicKey(t *testing.T) {
	privateKeyPEM, _, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	invalidPublicKey := "invalid-public-key"

	// Sign with valid private key
	j := NewRS384(privateKeyPEM)
	token, err := j.Sign(map[string]interface{}{
		"id": 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Try to verify with invalid public key
	jVerify := New(invalidPublicKey, &Options{
		Algorithm: AlgRS384,
	})

	_, err = jVerify.Verify(token)
	if err == nil {
		t.Fatal("Expected verification to fail with invalid public key")
	}

	if !strings.Contains(err.Error(), "failed to parse RSA public key") {
		t.Fatalf("Expected error to contain 'failed to parse RSA public key', got: %s", err.Error())
	}
}

func TestRS512AlgorithmMismatch(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Sign with RS512
	j := NewRS512(privateKeyPEM)
	token, err := j.Sign(map[string]interface{}{
		"id": 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Try to verify with RS256 algorithm - this should still work because
	// verification uses the algorithm from the token header, not the options
	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgRS256,
	})

	_, err = jVerify.Verify(token)
	if err != nil {
		t.Fatalf("Verification should succeed even with different algorithm option: %v", err)
	}
}

func TestRS384AlgorithmMismatch(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Sign with RS384
	j := NewRS384(privateKeyPEM)
	token, err := j.Sign(map[string]interface{}{
		"id": 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Try to verify with RS256 algorithm - this should still work because
	// verification uses the algorithm from the token header, not the options
	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgRS256,
	})

	_, err = jVerify.Verify(token)
	if err != nil {
		t.Fatalf("Verification should succeed even with different algorithm option: %v", err)
	}
}

func TestRS512CrossAlgorithmVerification(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Sign with RS512
	j := NewRS512(privateKeyPEM)
	token, err := j.Sign(map[string]interface{}{
		"id": 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Try to verify with RS384 algorithm - this should still work because
	// verification uses the algorithm from the token header, not the options
	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgRS384,
	})

	_, err = jVerify.Verify(token)
	if err != nil {
		t.Fatalf("Verification should succeed even with different algorithm option: %v", err)
	}
}

func TestRS384CrossAlgorithmVerification(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Sign with RS384
	j := NewRS384(privateKeyPEM)
	token, err := j.Sign(map[string]interface{}{
		"id": 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Try to verify with RS512 algorithm - this should still work because
	// verification uses the algorithm from the token header, not the options
	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgRS512,
	})

	_, err = jVerify.Verify(token)
	if err != nil {
		t.Fatalf("Verification should succeed even with different algorithm option: %v", err)
	}
}

func TestRS512WithCustomClaims(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	j := NewRS512(privateKeyPEM)
	j.SetIssuer("custom-issuer")
	j.SetSubject("custom-subject")
	j.SetAudience("custom-audience")
	j.SetNotBefore(time.Now().Unix() - 3600) // 1 hour ago
	j.SetJwtID("custom-jti-123")

	payload := map[string]interface{}{
		"user_id":     456,
		"role":        "super-admin",
		"permissions": []string{"read", "write", "delete"},
	}

	token, err := j.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgRS512,
	})

	payloadResult, err := jVerify.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	// Verify custom claims
	testify.Equal(t, payloadResult.Get("iss").String(), "custom-issuer")
	testify.Equal(t, payloadResult.Get("sub").String(), "custom-subject")
	testify.Equal(t, payloadResult.Get("aud").String(), "custom-audience")
	testify.Equal(t, payloadResult.Get("jti").String(), "custom-jti-123")
	testify.NotEqual(t, payloadResult.Get("nbf").Int64(), 0)

	// Verify payload content
	testify.Equal(t, payloadResult.Get("user_id").Int64(), int64(456))
	testify.Equal(t, payloadResult.Get("role").String(), "super-admin")
}

func TestRS384WithCustomClaims(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	j := NewRS384(privateKeyPEM)
	j.SetIssuer("custom-issuer")
	j.SetSubject("custom-subject")
	j.SetAudience("custom-audience")
	j.SetNotBefore(time.Now().Unix() - 3600) // 1 hour ago
	j.SetJwtID("custom-jti-456")

	payload := map[string]interface{}{
		"user_id":     789,
		"role":        "moderator",
		"permissions": []string{"read", "write"},
	}

	token, err := j.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgRS384,
	})

	payloadResult, err := jVerify.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	// Verify custom claims
	testify.Equal(t, payloadResult.Get("iss").String(), "custom-issuer")
	testify.Equal(t, payloadResult.Get("sub").String(), "custom-subject")
	testify.Equal(t, payloadResult.Get("aud").String(), "custom-audience")
	testify.Equal(t, payloadResult.Get("jti").String(), "custom-jti-456")
	testify.NotEqual(t, payloadResult.Get("nbf").Int64(), 0)

	// Verify payload content
	testify.Equal(t, payloadResult.Get("user_id").Int64(), int64(789))
	testify.Equal(t, payloadResult.Get("role").String(), "moderator")
}

func TestRS512UnsupportedAlgorithm(t *testing.T) {
	privateKeyPEM, _, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Try to sign with an unsupported algorithm
	_, err = Sign(privateKeyPEM, map[string]interface{}{
		"id": 1,
	}, &SignOptions{
		Algorithm: "UNSUPPORTED",
	})
	if err == nil {
		t.Fatal("Expected signing to fail with unsupported algorithm")
	}

	if !strings.Contains(err.Error(), "unsupported algorithm") {
		t.Fatalf("Expected error to contain 'unsupported algorithm', got: %s", err.Error())
	}
}

func TestRS384UnsupportedAlgorithm(t *testing.T) {
	privateKeyPEM, _, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Try to sign with an unsupported algorithm
	_, err = Sign(privateKeyPEM, map[string]interface{}{
		"id": 1,
	}, &SignOptions{
		Algorithm: "UNSUPPORTED",
	})
	if err == nil {
		t.Fatal("Expected signing to fail with unsupported algorithm")
	}

	if !strings.Contains(err.Error(), "unsupported algorithm") {
		t.Fatalf("Expected error to contain 'unsupported algorithm', got: %s", err.Error())
	}
}

func TestRS512EmptyPayload(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	j := NewRS512(privateKeyPEM)
	token, err := j.Sign(map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}

	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgRS512,
	})

	payload, err := jVerify.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	// Should have default claims even with empty payload
	testify.NotEqual(t, payload.Get("iat").Int64(), 0)
	testify.NotEqual(t, payload.Get("exp").Int64(), 0)
	testify.Equal(t, payload.Get("iss").String(), "go-zoox")
}

func TestRS384EmptyPayload(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	j := NewRS384(privateKeyPEM)
	token, err := j.Sign(map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}

	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgRS384,
	})

	payload, err := jVerify.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	// Should have default claims even with empty payload
	testify.NotEqual(t, payload.Get("iat").Int64(), 0)
	testify.NotEqual(t, payload.Get("exp").Int64(), 0)
	testify.Equal(t, payload.Get("iss").String(), "go-zoox")
}

func TestRS512LargePayload(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Create a large payload
	largePayload := map[string]interface{}{
		"user_id": 123,
		"data":    make([]string, 1000), // Large array
	}
	for i := 0; i < 1000; i++ {
		largePayload["data"].([]string)[i] = fmt.Sprintf("item-%d", i)
	}

	j := NewRS512(privateKeyPEM)
	token, err := j.Sign(largePayload)
	if err != nil {
		t.Fatal(err)
	}

	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgRS512,
	})

	payload, err := jVerify.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	testify.Equal(t, payload.Get("user_id").Int64(), int64(123))
	testify.NotEqual(t, payload.Get("data"), nil)
}

func TestRS384LargePayload(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Create a large payload
	largePayload := map[string]interface{}{
		"user_id": 456,
		"data":    make([]string, 1000), // Large array
	}
	for i := 0; i < 1000; i++ {
		largePayload["data"].([]string)[i] = fmt.Sprintf("item-%d", i)
	}

	j := NewRS384(privateKeyPEM)
	token, err := j.Sign(largePayload)
	if err != nil {
		t.Fatal(err)
	}

	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgRS384,
	})

	payload, err := jVerify.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	testify.Equal(t, payload.Get("user_id").Int64(), int64(456))
	testify.NotEqual(t, payload.Get("data"), nil)
}

func TestES256SignAndVerify(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestECDSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Test signing with ES256
	payload := map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
		"avatar":   "https://avatars.githubusercontent.com/u/7463687?v=4",
	}

	token, err := Sign(privateKeyPEM, payload, &SignOptions{
		Algorithm: AlgES256,
		IssuedAt:  1663218578,
		ExpiresAt: 2663225778,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Test verification with ES256
	header, payloadResult, err := Verify(publicKeyPEM, token)
	if err != nil {
		t.Fatal(err)
	}

	// Verify algorithm
	testify.Equal(t, AlgES256, header.Algorithm)

	// Verify payload content
	testify.Equal(t, payloadResult.Get("id").Float64(), 1.0)
	testify.Equal(t, payloadResult.Get("nickname").String(), "Zero")
	testify.Equal(t, payloadResult.Get("avatar").String(), "https://avatars.githubusercontent.com/u/7463687?v=4")
}

func TestES384SignAndVerify(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestECDSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Test signing with ES384
	payload := map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
		"avatar":   "https://avatars.githubusercontent.com/u/7463687?v=4",
	}

	token, err := Sign(privateKeyPEM, payload, &SignOptions{
		Algorithm: AlgES384,
		IssuedAt:  1663218578,
		ExpiresAt: 2663225778,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Test verification with ES384
	header, payloadResult, err := Verify(publicKeyPEM, token)
	if err != nil {
		t.Fatal(err)
	}

	// Verify algorithm
	testify.Equal(t, AlgES384, header.Algorithm)

	// Verify payload content
	testify.Equal(t, payloadResult.Get("id").Float64(), 1.0)
	testify.Equal(t, payloadResult.Get("nickname").String(), "Zero")
	testify.Equal(t, payloadResult.Get("avatar").String(), "https://avatars.githubusercontent.com/u/7463687?v=4")
}

func TestES512SignAndVerify(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestECDSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Test signing with ES512
	payload := map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
		"avatar":   "https://avatars.githubusercontent.com/u/7463687?v=4",
	}

	token, err := Sign(privateKeyPEM, payload, &SignOptions{
		Algorithm: AlgES512,
		IssuedAt:  1663218578,
		ExpiresAt: 2663225778,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Test verification with ES512
	header, payloadResult, err := Verify(publicKeyPEM, token)
	if err != nil {
		t.Fatal(err)
	}

	// Verify algorithm
	testify.Equal(t, AlgES512, header.Algorithm)

	// Verify payload content
	testify.Equal(t, payloadResult.Get("id").Float64(), 1.0)
	testify.Equal(t, payloadResult.Get("nickname").String(), "Zero")
	testify.Equal(t, payloadResult.Get("avatar").String(), "https://avatars.githubusercontent.com/u/7463687?v=4")
}

func TestES256JWT(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestECDSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Create JWT instance with ES256
	j := NewES256(privateKeyPEM)

	// Set custom options
	j.SetIssuer("test-issuer")
	j.SetSubject("test-subject")
	j.SetAudience("test-audience")
	j.SetIssuedAt(1663218578)
	j.SetExpiresAt(2663225778)

	payload := map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
		"avatar":   "https://avatars.githubusercontent.com/u/7463687?v=4",
	}

	// Sign the token
	token, err := j.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Create a new JWT instance for verification with public key
	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgES256,
	})

	// Verify the token
	payloadResult, err := jVerify.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	// Verify payload content
	testify.Equal(t, payloadResult.Get("id").Float64(), 1.0)
	testify.Equal(t, payloadResult.Get("nickname").String(), "Zero")
	testify.Equal(t, payloadResult.Get("avatar").String(), "https://avatars.githubusercontent.com/u/7463687?v=4")

	// Verify JWT claims from the verification result
	testify.Equal(t, payloadResult.Get("iss").String(), "test-issuer")
	testify.Equal(t, payloadResult.Get("sub").String(), "test-subject")
	testify.Equal(t, payloadResult.Get("aud").String(), "test-audience")
	testify.Equal(t, payloadResult.Get("iat").Int64(), int64(1663218578))
	testify.Equal(t, payloadResult.Get("exp").Int64(), int64(2663225778))
}

func TestES384JWT(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestECDSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Create JWT instance with ES384
	j := NewES384(privateKeyPEM)

	// Set custom options
	j.SetIssuer("test-issuer")
	j.SetSubject("test-subject")
	j.SetAudience("test-audience")
	j.SetIssuedAt(1663218578)
	j.SetExpiresAt(2663225778)

	payload := map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
		"avatar":   "https://avatars.githubusercontent.com/u/7463687?v=4",
	}

	// Sign the token
	token, err := j.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Create a new JWT instance for verification with public key
	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgES384,
	})

	// Verify the token
	payloadResult, err := jVerify.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	// Verify payload content
	testify.Equal(t, payloadResult.Get("id").Float64(), 1.0)
	testify.Equal(t, payloadResult.Get("nickname").String(), "Zero")
	testify.Equal(t, payloadResult.Get("avatar").String(), "https://avatars.githubusercontent.com/u/7463687?v=4")

	// Verify JWT claims from the verification result
	testify.Equal(t, payloadResult.Get("iss").String(), "test-issuer")
	testify.Equal(t, payloadResult.Get("sub").String(), "test-subject")
	testify.Equal(t, payloadResult.Get("aud").String(), "test-audience")
	testify.Equal(t, payloadResult.Get("iat").Int64(), int64(1663218578))
	testify.Equal(t, payloadResult.Get("exp").Int64(), int64(2663225778))
}

func TestES512JWT(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestECDSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Create JWT instance with ES512
	j := NewES512(privateKeyPEM)

	// Set custom options
	j.SetIssuer("test-issuer")
	j.SetSubject("test-subject")
	j.SetAudience("test-audience")
	j.SetIssuedAt(1663218578)
	j.SetExpiresAt(2663225778)

	payload := map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
		"avatar":   "https://avatars.githubusercontent.com/u/7463687?v=4",
	}

	// Sign the token
	token, err := j.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Create a new JWT instance for verification with public key
	jVerify := New(publicKeyPEM, &Options{
		Algorithm: AlgES512,
	})

	// Verify the token
	payloadResult, err := jVerify.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	// Verify payload content
	testify.Equal(t, payloadResult.Get("id").Float64(), 1.0)
	testify.Equal(t, payloadResult.Get("nickname").String(), "Zero")
	testify.Equal(t, payloadResult.Get("avatar").String(), "https://avatars.githubusercontent.com/u/7463687?v=4")

	// Verify JWT claims from the verification result
	testify.Equal(t, payloadResult.Get("iss").String(), "test-issuer")
	testify.Equal(t, payloadResult.Get("sub").String(), "test-subject")
	testify.Equal(t, payloadResult.Get("aud").String(), "test-audience")
	testify.Equal(t, payloadResult.Get("iat").Int64(), int64(1663218578))
	testify.Equal(t, payloadResult.Get("exp").Int64(), int64(2663225778))
}


func TestPS256SignAndVerify(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	payload := map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
	}

	token, err := Sign(privateKeyPEM, payload, &SignOptions{
		Algorithm: AlgPS256,
		IssuedAt:  1663218578,
		ExpiresAt: 2663225778,
	})
	if err != nil {
		t.Fatal(err)
	}

	header, payloadResult, err := Verify(publicKeyPEM, token)
	if err != nil {
		t.Fatal(err)
	}

	testify.Equal(t, AlgPS256, header.Algorithm)
	testify.Equal(t, payloadResult.Get("id").Float64(), 1.0)
	testify.Equal(t, payloadResult.Get("nickname").String(), "Zero")
}

func TestPS384SignAndVerify(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	payload := map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
	}

	token, err := Sign(privateKeyPEM, payload, &SignOptions{
		Algorithm: AlgPS384,
		IssuedAt:  1663218578,
		ExpiresAt: 2663225778,
	})
	if err != nil {
		t.Fatal(err)
	}

	header, payloadResult, err := Verify(publicKeyPEM, token)
	if err != nil {
		t.Fatal(err)
	}

	testify.Equal(t, AlgPS384, header.Algorithm)
	testify.Equal(t, payloadResult.Get("id").Float64(), 1.0)
	testify.Equal(t, payloadResult.Get("nickname").String(), "Zero")
}

func TestPS512SignAndVerify(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	payload := map[string]interface{}{
		"id":       1,
		"nickname": "Zero",
	}

	token, err := Sign(privateKeyPEM, payload, &SignOptions{
		Algorithm: AlgPS512,
		IssuedAt:  1663218578,
		ExpiresAt: 2663225778,
	})
	if err != nil {
		t.Fatal(err)
	}

	header, payloadResult, err := Verify(publicKeyPEM, token)
	if err != nil {
		t.Fatal(err)
	}

	testify.Equal(t, AlgPS512, header.Algorithm)
	testify.Equal(t, payloadResult.Get("id").Float64(), 1.0)
	testify.Equal(t, payloadResult.Get("nickname").String(), "Zero")
}
