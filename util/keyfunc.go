package util

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// KnownKeyfunc is a helper for generating a Keyfunc from a known
// signing method and key. If your implementation only supports a single signing method
// and key, this is for you.
func KnownKeyfunc(signingMethod jwt.SigningMethod, key interface{}) jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		if signingMethod.Alg() != t.Header["alg"] {
			return nil, fmt.Errorf("unexpected signing method: %v, expected: %v", t.Header["alg"], signingMethod.Alg())
		}
		return key, nil
	}
}