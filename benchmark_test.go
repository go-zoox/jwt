package jwt

import (
	"testing"
)

// BenchmarkHS256Sign benchmarks HS256 signing performance
func BenchmarkHS256Sign(b *testing.B) {
	j := NewHS256("test-secret-key-for-benchmarking")
	payload := map[string]interface{}{
		"user_id": 123,
		"role":    "admin",
		"email":   "test@example.com",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := j.Sign(payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHS256Verify benchmarks HS256 verification performance
func BenchmarkHS256Verify(b *testing.B) {
	j := NewHS256("test-secret-key-for-benchmarking")
	payload := map[string]interface{}{
		"user_id": 123,
		"role":    "admin",
		"email":   "test@example.com",
	}
	
	token, err := j.Sign(payload)
	if err != nil {
		b.Fatal(err)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := j.Verify(token)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRS256Sign benchmarks RS256 signing performance
func BenchmarkRS256Sign(b *testing.B) {
	privateKeyPEM, _, err := generateTestRSAKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	
	j := NewRS256(privateKeyPEM)
	payload := map[string]interface{}{
		"user_id": 123,
		"role":    "admin",
		"email":   "test@example.com",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := j.Sign(payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRS256Verify benchmarks RS256 verification performance
func BenchmarkRS256Verify(b *testing.B) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	
	j := NewRS256(privateKeyPEM)
	jVerify := New(publicKeyPEM, &Options{Algorithm: AlgRS256})
	
	payload := map[string]interface{}{
		"user_id": 123,
		"role":    "admin",
		"email":   "test@example.com",
	}
	
	token, err := j.Sign(payload)
	if err != nil {
		b.Fatal(err)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := jVerify.Verify(token)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkES256Sign benchmarks ES256 signing performance
func BenchmarkES256Sign(b *testing.B) {
	privateKeyPEM, _, err := generateTestECDSAKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	
	j := NewES256(privateKeyPEM)
	payload := map[string]interface{}{
		"user_id": 123,
		"role":    "admin",
		"email":   "test@example.com",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := j.Sign(payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkES256Verify benchmarks ES256 verification performance
func BenchmarkES256Verify(b *testing.B) {
	privateKeyPEM, publicKeyPEM, err := generateTestECDSAKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	
	j := NewES256(privateKeyPEM)
	jVerify := New(publicKeyPEM, &Options{Algorithm: AlgES256})
	
	payload := map[string]interface{}{
		"user_id": 123,
		"role":    "admin",
		"email":   "test@example.com",
	}
	
	token, err := j.Sign(payload)
	if err != nil {
		b.Fatal(err)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := jVerify.Verify(token)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPS256Sign benchmarks PS256 signing performance
func BenchmarkPS256Sign(b *testing.B) {
	privateKeyPEM, _, err := generateTestRSAKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	
	j := NewPS256(privateKeyPEM)
	payload := map[string]interface{}{
		"user_id": 123,
		"role":    "admin",
		"email":   "test@example.com",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := j.Sign(payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPS256Verify benchmarks PS256 verification performance
func BenchmarkPS256Verify(b *testing.B) {
	privateKeyPEM, publicKeyPEM, err := generateTestRSAKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	
	j := NewPS256(privateKeyPEM)
	jVerify := New(publicKeyPEM, &Options{Algorithm: AlgPS256})
	
	payload := map[string]interface{}{
		"user_id": 123,
		"role":    "admin",
		"email":   "test@example.com",
	}
	
	token, err := j.Sign(payload)
	if err != nil {
		b.Fatal(err)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := jVerify.Verify(token)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBuilderPattern benchmarks the builder pattern performance
func BenchmarkBuilderPattern(b *testing.B) {
	payload := map[string]interface{}{
		"user_id": 123,
		"role":    "admin",
		"email":   "test@example.com",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token, err := BuildHS256("test-secret").
			WithIssuer("test-issuer").
			WithSubject("test-subject").
			WithExpiresIn(3600).
			BuildAndSign(payload)
		if err != nil {
			b.Fatal(err)
		}
		_ = token
	}
}

// BenchmarkKeyCache benchmarks key caching performance
func BenchmarkKeyCache(b *testing.B) {
	privateKeyPEM, _, err := generateTestRSAKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	
	// First, populate the cache
	_, err = parseRSAPrivateKey(privateKeyPEM)
	if err != nil {
		b.Fatal(err)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := parseRSAPrivateKey(privateKeyPEM)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAlgorithmRegistry benchmarks algorithm registry performance
func BenchmarkAlgorithmRegistry(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler, err := globalRegistry.Get(AlgHS256)
		if err != nil {
			b.Fatal(err)
		}
		_ = handler
	}
}
