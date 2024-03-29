package validation

import (
	"github.com/golang-jwt/jwt/v5"
)

type JKUValidationFunc func(jkuUrl, uaaDomain string) (bool, error)
type JWTValidationFunc func(decodedToken *jwt.Token, clientId, xsAppName string) (bool, error)