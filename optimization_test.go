package jwt

import (
	"crypto"
	"testing"

	"github.com/go-zoox/testify"
)

// TestKeyCache tests the key caching functionality
func TestKeyCache(t *testing.T) {
	cache := NewKeyCache()
	
	// Test RSA private key caching
	privateKeyPEM, _, err := generateTestRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	
	// Parse and cache the key
	parsedKey, err := parseRSAPrivateKey(privateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	
	cache.SetRSAPrivateKey(privateKeyPEM, parsedKey)
	
	// Retrieve from cache
	cachedKey := cache.GetRSAPrivateKey(privateKeyPEM)
	testify.NotEqual(t, cachedKey, nil)
	testify.Equal(t, parsedKey, cachedKey)
	
	// Test cache miss
	nonExistentKey := cache.GetRSAPrivateKey("non-existent-key")
	testify.Equal(t, nonExistentKey, nil)
	
	// Test cache clear
	cache.Clear()
	clearedKey := cache.GetRSAPrivateKey(privateKeyPEM)
	testify.Equal(t, clearedKey, nil)
}

// TestJWTError tests the custom JWT error types
func TestJWTError(t *testing.T) {
	// Test basic error
	err := NewJWTError("test_type", "test message", nil)
	testify.Equal(t, "JWT test_type error: test message", err.Error())
	testify.Equal(t, "test_type", err.Type)
	testify.Equal(t, "test message", err.Message)
	
	// Test specific error types
	invalidTokenErr := NewInvalidTokenError("invalid token", nil)
	testify.Equal(t, ErrTypeInvalidToken, invalidTokenErr.Type)
	
	expiredTokenErr := NewExpiredTokenError("token expired")
	testify.Equal(t, ErrTypeExpiredToken, expiredTokenErr.Type)
	
	unsupportedAlgErr := NewUnsupportedAlgorithmError("INVALID")
	testify.Equal(t, ErrTypeUnsupportedAlg, unsupportedAlgErr.Type)
}

// TestAlgorithmRegistry tests the algorithm registry functionality
func TestAlgorithmRegistry(t *testing.T) {
	registry := NewAlgorithmRegistry()
	
	// Test getting a registered algorithm
	handler, err := registry.Get(AlgHS256)
	if err != nil {
		t.Fatal(err)
	}
	if handler == nil {
		t.Fatal("handler should not be nil")
	}
	testify.Equal(t, AlgHS256, handler.GetAlgorithm())
	
	// Test getting an unregistered algorithm
	_, err = registry.Get("INVALID")
	if err == nil {
		t.Fatal("should return error for invalid algorithm")
	}
	
	// Test listing algorithms
	algorithms := registry.List()
	if len(algorithms) == 0 {
		t.Fatal("should have algorithms")
	}
}

// TestBuilderPattern tests the builder pattern functionality
func TestBuilderPattern(t *testing.T) {
	// Test basic builder
	jwt := NewBuilder().
		WithSecret("test-secret").
		WithAlgorithm(AlgHS256).
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		WithAudience("test-audience").
		WithExpiresIn(3600).
		WithIssuedNow().
		Build()
	
	if jwt == nil {
		t.Fatal("jwt should not be nil")
	}
	testify.Equal(t, AlgHS256, jwt.GetAlgorithm())
	
	// Test convenience methods
	hs256JWT := BuildHS256("test-secret").
		WithIssuer("test-issuer").
		WithExpiresIn(3600).
		Build()
	
	if hs256JWT == nil {
		t.Fatal("hs256JWT should not be nil")
	}
	testify.Equal(t, AlgHS256, hs256JWT.GetAlgorithm())
	
	// Test BuildAndSign
	payload := map[string]interface{}{
		"user_id": 123,
		"role":    "admin",
	}
	
	token, err := BuildHS256("test-secret").
		WithIssuer("test-issuer").
		BuildAndSign(payload)
	
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("token should not be empty")
	}
	
	// Verify the token
	jwtVerify := NewHS256("test-secret")
	verifiedPayload, err := jwtVerify.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	testify.Equal(t, float64(123), verifiedPayload.Get("user_id").Float64())
	testify.Equal(t, "admin", verifiedPayload.Get("role").String())
}

// TestHasherPool tests the hasher pool functionality
func TestHasherPool(t *testing.T) {
	pool := NewHasherPool()
	
	// Test SHA256 pool
	hasher1 := pool.GetSHA256()
	if hasher1 == nil {
		t.Fatal("hasher1 should not be nil")
	}
	pool.PutSHA256(hasher1)
	
	hasher2 := pool.GetSHA256()
	if hasher2 == nil {
		t.Fatal("hasher2 should not be nil")
	}
	pool.PutSHA256(hasher2)
	
	// Test SHA384 pool
	hasher384 := pool.GetSHA384()
	if hasher384 == nil {
		t.Fatal("hasher384 should not be nil")
	}
	pool.PutSHA384(hasher384)
	
	// Test SHA512 pool
	hasher512 := pool.GetSHA512()
	if hasher512 == nil {
		t.Fatal("hasher512 should not be nil")
	}
	pool.PutSHA512(hasher512)
}

// TestConstantTimeEqual tests the constant time comparison function
func TestConstantTimeEqual(t *testing.T) {
	// Test equal arrays
	a := []byte("test")
	b := []byte("test")
	if !constantTimeEqual(a, b) {
		t.Fatal("equal arrays should return true")
	}
	
	// Test different arrays
	c := []byte("different")
	if constantTimeEqual(a, c) {
		t.Fatal("different arrays should return false")
	}
	
	// Test different lengths
	d := []byte("test1")
	if constantTimeEqual(a, d) {
		t.Fatal("different length arrays should return false")
	}
	
	// Test empty arrays
	e := []byte("")
	f := []byte("")
	if !constantTimeEqual(e, f) {
		t.Fatal("empty arrays should return true")
	}
}

// TestAlgorithmHandlers tests the algorithm handler implementations
func TestAlgorithmHandlers(t *testing.T) {
	// Test HMAC handler
	hmacHandler := NewHMACHandler(AlgHS256, crypto.SHA256)
	testify.Equal(t, AlgHS256, hmacHandler.GetAlgorithm())
	
	data := []byte("test data")
	secret := "test-secret"
	
	signature, err := hmacHandler.Sign(secret, data)
	if err != nil {
		t.Fatal(err)
	}
	if signature == nil {
		t.Fatal("signature should not be nil")
	}
	
	err = hmacHandler.Verify(secret, data, signature)
	if err != nil {
		t.Fatal(err)
	}
	
	// Test with wrong secret
	wrongSecret := "wrong-secret"
	err = hmacHandler.Verify(wrongSecret, data, signature)
	if err == nil {
		t.Fatal("should return error for wrong secret")
	}
}

// TestGlobalInstances tests the global instances
func TestGlobalInstances(t *testing.T) {
	// Test global key cache
	if globalKeyCache == nil {
		t.Fatal("globalKeyCache should not be nil")
	}
	
	// Test global hasher pool
	if globalHasherPool == nil {
		t.Fatal("globalHasherPool should not be nil")
	}
	
	// Test global registry
	if globalRegistry == nil {
		t.Fatal("globalRegistry should not be nil")
	}
	
	// Test registry has all algorithms
	algorithms := globalRegistry.List()
	if len(algorithms) == 0 {
		t.Fatal("should have algorithms")
	}
}
