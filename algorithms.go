package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"fmt"

	"github.com/go-zoox/crypto/hmac"
)

// AlgorithmHandler defines the interface for JWT algorithm handlers
type AlgorithmHandler interface {
	Sign(secret string, data []byte) ([]byte, error)
	Verify(secret string, data []byte, signature []byte) error
	GetAlgorithm() string
}

// HMACHandler handles HMAC-based algorithms
type HMACHandler struct {
	algorithm string
	hashFunc  crypto.Hash
}

// NewHMACHandler creates a new HMAC handler
func NewHMACHandler(algorithm string, hashFunc crypto.Hash) *HMACHandler {
	return &HMACHandler{
		algorithm: algorithm,
		hashFunc:  hashFunc,
	}
}

// Sign implements AlgorithmHandler for HMAC
func (h *HMACHandler) Sign(secret string, data []byte) ([]byte, error) {
	// Check cache first
	if cachedKey := globalKeyCache.GetRSAPrivateKey(secret); cachedKey != nil {
		// This is a placeholder - HMAC doesn't use RSA keys
		// In practice, HMAC uses the secret directly
	}
	
	// Use HMAC for signing based on hash function
	var hmacResult string
	switch h.hashFunc {
	case crypto.SHA256:
		hmacResult = hmac.Sha256(secret, string(data), "base64")
	case crypto.SHA384:
		hmacResult = hmac.Sha384(secret, string(data), "base64")
	case crypto.SHA512:
		hmacResult = hmac.Sha512(secret, string(data), "base64")
	default:
		return nil, NewUnsupportedAlgorithmError(fmt.Sprintf("unsupported hash function: %v", h.hashFunc))
	}
	
	return []byte(hmacResult), nil
}

// constantTimeEqual performs constant time comparison to prevent timing attacks
func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Verify implements AlgorithmHandler for HMAC
func (h *HMACHandler) Verify(secret string, data []byte, signature []byte) error {
	expectedSignature, err := h.Sign(secret, data)
	if err != nil {
		return NewVerifyError("failed to generate expected signature", err)
	}
	
	if !constantTimeEqual(signature, expectedSignature) {
		return NewInvalidSignatureError("signature verification failed", nil)
	}
	
	return nil
}

// GetAlgorithm returns the algorithm name
func (h *HMACHandler) GetAlgorithm() string {
	return h.algorithm
}

// RSAHandler handles RSA-based algorithms
type RSAHandler struct {
	algorithm string
	hashFunc  crypto.Hash
	padding   string // "PKCS1v15" or "PSS"
}

// NewRSAHandler creates a new RSA handler
func NewRSAHandler(algorithm string, hashFunc crypto.Hash, padding string) *RSAHandler {
	return &RSAHandler{
		algorithm: algorithm,
		hashFunc:  hashFunc,
		padding:   padding,
	}
}

// Sign implements AlgorithmHandler for RSA
func (r *RSAHandler) Sign(secret string, data []byte) ([]byte, error) {
	// Check cache first
	privateKey := globalKeyCache.GetRSAPrivateKey(secret)
	if privateKey == nil {
		// Parse and cache the key
		parsedKey, err := parseRSAPrivateKey(secret)
		if err != nil {
			return nil, NewInvalidKeyError("failed to parse RSA private key", err)
		}
		globalKeyCache.SetRSAPrivateKey(secret, parsedKey)
		privateKey = parsedKey
	}
	
	// Create hash
	hasher := r.hashFunc.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)
	
	// Sign based on padding type
	var signature []byte
	var err error
	
	switch r.padding {
	case "PKCS1v15":
		signature, err = rsa.SignPKCS1v15(nil, privateKey, r.hashFunc, hashed)
	case "PSS":
		signature, err = rsa.SignPSS(rand.Reader, privateKey, r.hashFunc, hashed, nil)
	default:
		return nil, NewUnsupportedAlgorithmError(fmt.Sprintf("unsupported RSA padding: %s", r.padding))
	}
	
	if err != nil {
		return nil, NewSignError("failed to sign with RSA", err)
	}
	
	return signature, nil
}

// Verify implements AlgorithmHandler for RSA
func (r *RSAHandler) Verify(secret string, data []byte, signature []byte) error {
	// Check cache first
	publicKey := globalKeyCache.GetRSAPublicKey(secret)
	if publicKey == nil {
		// Parse and cache the key
		parsedKey, err := parseRSAPublicKey(secret)
		if err != nil {
			return NewInvalidKeyError("failed to parse RSA public key", err)
		}
		globalKeyCache.SetRSAPublicKey(secret, parsedKey)
		publicKey = parsedKey
	}
	
	// Create hash
	hasher := r.hashFunc.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)
	
	// Verify based on padding type
	var err error
	
	switch r.padding {
	case "PKCS1v15":
		err = rsa.VerifyPKCS1v15(publicKey, r.hashFunc, hashed, signature)
	case "PSS":
		err = rsa.VerifyPSS(publicKey, r.hashFunc, hashed, signature, nil)
	default:
		return NewUnsupportedAlgorithmError(fmt.Sprintf("unsupported RSA padding: %s", r.padding))
	}
	
	if err != nil {
		return NewInvalidSignatureError("RSA signature verification failed", err)
	}
	
	return nil
}

// GetAlgorithm returns the algorithm name
func (r *RSAHandler) GetAlgorithm() string {
	return r.algorithm
}

// ECDSAHandler handles ECDSA-based algorithms
type ECDSAHandler struct {
	algorithm string
	hashFunc  crypto.Hash
}

// NewECDSAHandler creates a new ECDSA handler
func NewECDSAHandler(algorithm string, hashFunc crypto.Hash) *ECDSAHandler {
	return &ECDSAHandler{
		algorithm: algorithm,
		hashFunc:  hashFunc,
	}
}

// Sign implements AlgorithmHandler for ECDSA
func (e *ECDSAHandler) Sign(secret string, data []byte) ([]byte, error) {
	// Check cache first
	privateKey := globalKeyCache.GetECDSAPrivateKey(secret)
	if privateKey == nil {
		// Parse and cache the key
		parsedKey, err := parseECDSAPrivateKey(secret)
		if err != nil {
			return nil, NewInvalidKeyError("failed to parse ECDSA private key", err)
		}
		globalKeyCache.SetECDSAPrivateKey(secret, parsedKey)
		privateKey = parsedKey
	}
	
	// Create hash
	hasher := e.hashFunc.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)
	
	// Sign
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed)
	if err != nil {
		return nil, NewSignError("failed to sign with ECDSA", err)
	}
	
	// Encode signature
	signature := encodeECDSASignature(r, s)
	return signature, nil
}

// Verify implements AlgorithmHandler for ECDSA
func (e *ECDSAHandler) Verify(secret string, data []byte, signature []byte) error {
	// Check cache first
	publicKey := globalKeyCache.GetECDSAPublicKey(secret)
	if publicKey == nil {
		// Parse and cache the key
		parsedKey, err := parseECDSAPublicKey(secret)
		if err != nil {
			return NewInvalidKeyError("failed to parse ECDSA public key", err)
		}
		globalKeyCache.SetECDSAPublicKey(secret, parsedKey)
		publicKey = parsedKey
	}
	
	// Create hash
	hasher := e.hashFunc.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)
	
	// Decode signature
	r, s, err := decodeECDSASignature(signature)
	if err != nil {
		return NewVerifyError("failed to decode ECDSA signature", err)
	}
	
	// Verify
	if !ecdsa.Verify(publicKey, hashed, r, s) {
		return NewInvalidSignatureError("ECDSA signature verification failed", nil)
	}
	
	return nil
}

// GetAlgorithm returns the algorithm name
func (e *ECDSAHandler) GetAlgorithm() string {
	return e.algorithm
}

// AlgorithmRegistry manages algorithm handlers
type AlgorithmRegistry struct {
	handlers map[string]AlgorithmHandler
}

// NewAlgorithmRegistry creates a new algorithm registry
func NewAlgorithmRegistry() *AlgorithmRegistry {
	registry := &AlgorithmRegistry{
		handlers: make(map[string]AlgorithmHandler),
	}
	
	// Register default algorithms
	registry.RegisterDefaultAlgorithms()
	
	return registry
}

// RegisterDefaultAlgorithms registers all supported algorithms
func (r *AlgorithmRegistry) RegisterDefaultAlgorithms() {
	// HMAC algorithms
	r.Register(AlgHS256, NewHMACHandler(AlgHS256, crypto.SHA256))
	r.Register(AlgHS384, NewHMACHandler(AlgHS384, crypto.SHA384))
	r.Register(AlgHS512, NewHMACHandler(AlgHS512, crypto.SHA512))
	
	// RSA algorithms
	r.Register(AlgRS256, NewRSAHandler(AlgRS256, crypto.SHA256, "PKCS1v15"))
	r.Register(AlgRS384, NewRSAHandler(AlgRS384, crypto.SHA384, "PKCS1v15"))
	r.Register(AlgRS512, NewRSAHandler(AlgRS512, crypto.SHA512, "PKCS1v15"))
	
	// RSA-PSS algorithms
	r.Register(AlgPS256, NewRSAHandler(AlgPS256, crypto.SHA256, "PSS"))
	r.Register(AlgPS384, NewRSAHandler(AlgPS384, crypto.SHA384, "PSS"))
	r.Register(AlgPS512, NewRSAHandler(AlgPS512, crypto.SHA512, "PSS"))
	
	// ECDSA algorithms
	r.Register(AlgES256, NewECDSAHandler(AlgES256, crypto.SHA256))
	r.Register(AlgES384, NewECDSAHandler(AlgES384, crypto.SHA384))
	r.Register(AlgES512, NewECDSAHandler(AlgES512, crypto.SHA512))
}

// Register registers an algorithm handler
func (r *AlgorithmRegistry) Register(algorithm string, handler AlgorithmHandler) {
	r.handlers[algorithm] = handler
}

// Get retrieves an algorithm handler
func (r *AlgorithmRegistry) Get(algorithm string) (AlgorithmHandler, error) {
	handler, exists := r.handlers[algorithm]
	if !exists {
		return nil, NewUnsupportedAlgorithmError(algorithm)
	}
	return handler, nil
}

// List returns all registered algorithms
func (r *AlgorithmRegistry) List() []string {
	algorithms := make([]string, 0, len(r.handlers))
	for alg := range r.handlers {
		algorithms = append(algorithms, alg)
	}
	return algorithms
}

// Global registry instance
var globalRegistry = NewAlgorithmRegistry()
