package jwt

import (
	"fmt"
)

// JWTError represents a JWT-specific error with type and context
type JWTError struct {
	Type    string
	Message string
	Cause   error
}

// Error implements the error interface
func (e *JWTError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("JWT %s error: %s (caused by: %v)", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("JWT %s error: %s", e.Type, e.Message)
}

// Unwrap returns the underlying error
func (e *JWTError) Unwrap() error {
	return e.Cause
}

// Error types
const (
	ErrTypeInvalidToken     = "invalid_token"
	ErrTypeInvalidSignature = "invalid_signature"
	ErrTypeExpiredToken     = "expired_token"
	ErrTypeInvalidKey       = "invalid_key"
	ErrTypeUnsupportedAlg   = "unsupported_algorithm"
	ErrTypeInvalidClaims     = "invalid_claims"
	ErrTypeParseError        = "parse_error"
	ErrTypeSignError         = "sign_error"
	ErrTypeVerifyError       = "verify_error"
)

// NewJWTError creates a new JWT error
func NewJWTError(errorType, message string, cause error) *JWTError {
	return &JWTError{
		Type:    errorType,
		Message: message,
		Cause:   cause,
	}
}

// NewInvalidTokenError creates an invalid token error
func NewInvalidTokenError(message string, cause error) *JWTError {
	return NewJWTError(ErrTypeInvalidToken, message, cause)
}

// NewInvalidSignatureError creates an invalid signature error
func NewInvalidSignatureError(message string, cause error) *JWTError {
	return NewJWTError(ErrTypeInvalidSignature, message, cause)
}

// NewExpiredTokenError creates an expired token error
func NewExpiredTokenError(message string) *JWTError {
	return NewJWTError(ErrTypeExpiredToken, message, nil)
}

// NewInvalidKeyError creates an invalid key error
func NewInvalidKeyError(message string, cause error) *JWTError {
	return NewJWTError(ErrTypeInvalidKey, message, cause)
}

// NewUnsupportedAlgorithmError creates an unsupported algorithm error
func NewUnsupportedAlgorithmError(algorithm string) *JWTError {
	return NewJWTError(ErrTypeUnsupportedAlg, fmt.Sprintf("algorithm %s is not supported", algorithm), nil)
}

// NewInvalidClaimsError creates an invalid claims error
func NewInvalidClaimsError(message string, cause error) *JWTError {
	return NewJWTError(ErrTypeInvalidClaims, message, cause)
}

// NewParseError creates a parse error
func NewParseError(message string, cause error) *JWTError {
	return NewJWTError(ErrTypeParseError, message, cause)
}

// NewSignError creates a sign error
func NewSignError(message string, cause error) *JWTError {
	return NewJWTError(ErrTypeSignError, message, cause)
}

// NewVerifyError creates a verify error
func NewVerifyError(message string, cause error) *JWTError {
	return NewJWTError(ErrTypeVerifyError, message, cause)
}
