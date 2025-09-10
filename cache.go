package jwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"sync"
)

// KeyCache provides caching for parsed cryptographic keys
type KeyCache struct {
	rsaPrivateKeys  map[string]*rsa.PrivateKey
	rsaPublicKeys   map[string]*rsa.PublicKey
	ecdsaPrivateKeys map[string]*ecdsa.PrivateKey
	ecdsaPublicKeys  map[string]*ecdsa.PublicKey
	mutex           sync.RWMutex
}

// NewKeyCache creates a new key cache instance
func NewKeyCache() *KeyCache {
	return &KeyCache{
		rsaPrivateKeys:  make(map[string]*rsa.PrivateKey),
		rsaPublicKeys:   make(map[string]*rsa.PublicKey),
		ecdsaPrivateKeys: make(map[string]*ecdsa.PrivateKey),
		ecdsaPublicKeys:  make(map[string]*ecdsa.PublicKey),
	}
}

// GetRSAPrivateKey retrieves a cached RSA private key or returns nil if not found
func (c *KeyCache) GetRSAPrivateKey(key string) *rsa.PrivateKey {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.rsaPrivateKeys[key]
}

// SetRSAPrivateKey caches an RSA private key
func (c *KeyCache) SetRSAPrivateKey(key string, privateKey *rsa.PrivateKey) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.rsaPrivateKeys[key] = privateKey
}

// GetRSAPublicKey retrieves a cached RSA public key or returns nil if not found
func (c *KeyCache) GetRSAPublicKey(key string) *rsa.PublicKey {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.rsaPublicKeys[key]
}

// SetRSAPublicKey caches an RSA public key
func (c *KeyCache) SetRSAPublicKey(key string, publicKey *rsa.PublicKey) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.rsaPublicKeys[key] = publicKey
}

// GetECDSAPrivateKey retrieves a cached ECDSA private key or returns nil if not found
func (c *KeyCache) GetECDSAPrivateKey(key string) *ecdsa.PrivateKey {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.ecdsaPrivateKeys[key]
}

// SetECDSAPrivateKey caches an ECDSA private key
func (c *KeyCache) SetECDSAPrivateKey(key string, privateKey *ecdsa.PrivateKey) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.ecdsaPrivateKeys[key] = privateKey
}

// GetECDSAPublicKey retrieves a cached ECDSA public key or returns nil if not found
func (c *KeyCache) GetECDSAPublicKey(key string) *ecdsa.PublicKey {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.ecdsaPublicKeys[key]
}

// SetECDSAPublicKey caches an ECDSA public key
func (c *KeyCache) SetECDSAPublicKey(key string, publicKey *ecdsa.PublicKey) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.ecdsaPublicKeys[key] = publicKey
}

// Clear clears all cached keys
func (c *KeyCache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.rsaPrivateKeys = make(map[string]*rsa.PrivateKey)
	c.rsaPublicKeys = make(map[string]*rsa.PublicKey)
	c.ecdsaPrivateKeys = make(map[string]*ecdsa.PrivateKey)
	c.ecdsaPublicKeys = make(map[string]*ecdsa.PublicKey)
}

// HasherPool provides a pool of hash functions to reduce memory allocations
type HasherPool struct {
	sha256Pool sync.Pool
	sha384Pool sync.Pool
	sha512Pool sync.Pool
}

// NewHasherPool creates a new hasher pool
func NewHasherPool() *HasherPool {
	return &HasherPool{
		sha256Pool: sync.Pool{
			New: func() interface{} {
				return sha256.New()
			},
		},
		sha384Pool: sync.Pool{
			New: func() interface{} {
				return sha512.New384()
			},
		},
		sha512Pool: sync.Pool{
			New: func() interface{} {
				return sha512.New()
			},
		},
	}
}

// GetSHA256 gets a SHA256 hasher from the pool
func (p *HasherPool) GetSHA256() interface{} {
	return p.sha256Pool.Get()
}

// PutSHA256 returns a SHA256 hasher to the pool
func (p *HasherPool) PutSHA256(hasher interface{}) {
	p.sha256Pool.Put(hasher)
}

// GetSHA384 gets a SHA384 hasher from the pool
func (p *HasherPool) GetSHA384() interface{} {
	return p.sha384Pool.Get()
}

// PutSHA384 returns a SHA384 hasher to the pool
func (p *HasherPool) PutSHA384(hasher interface{}) {
	p.sha384Pool.Put(hasher)
}

// GetSHA512 gets a SHA512 hasher from the pool
func (p *HasherPool) GetSHA512() interface{} {
	return p.sha512Pool.Get()
}

// PutSHA512 returns a SHA512 hasher to the pool
func (p *HasherPool) PutSHA512(hasher interface{}) {
	p.sha512Pool.Put(hasher)
}

// Global instances
var (
	globalKeyCache  = NewKeyCache()
	globalHasherPool = NewHasherPool()
)
