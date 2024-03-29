package verification

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/patrickmn/go-cache"
	"github.com/yogeshberia/cloud-security-client-golang-xsuaa/config"
	"github.com/yogeshberia/cloud-security-client-golang-xsuaa/validation"
)

// function with no cache implementation --> Each time a validation is made, the public key is been downloaded!
func ValidationKeyGetter(xsuaaConfig config.XsuaaConfig, validateJKU validation.JKUValidationFunc) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {

		if token.Header["jku"] == nil {
			return nil, errors.New("no jku in header available to validate trust")
		}

		uuaDomain := xsuaaConfig.UaaDomain
		jkuUrl := token.Header["jku"].(string)
		tokenUrl := jkuUrl

		if jkuUrl == "" {
			return nil, errors.New("no jku in header available to validate trust")
		}

		// check if jku url corresponds to xsuaa url been bound to the app
		if isValid, err := validateJKU(jkuUrl, uuaDomain); !isValid && err != nil {
			return nil, err
		}

		keyID, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("expecting JWT header to have string kid")
		}

		jwks, err := jwk.Fetch(context.Background(), tokenUrl)
		if err != nil {
			return nil, errors.New("can't fetch public JWKS")
		}

		if key, found := jwks.LookupKeyID(keyID); found {

			var rawKey interface{}
			if err := key.Raw(&rawKey); err != nil {
				return nil, err
			} else {
				return rawKey, nil
			}
		}

		return nil, fmt.Errorf("unable to find key %q", keyID)

	}

}

func ValidationKeyGetterWithCacheDefault(xsuaaConfig config.XsuaaConfig, configCache *cache.Cache) jwt.Keyfunc {

	return ValidationKeyGetterWithCacheConfigurable(xsuaaConfig, validation.JKUValidator, configCache)

}

// cache been injected and managed from outside (usually in the middleware)
func ValidationKeyGetterWithCacheConfigurable(xsuaaConfig config.XsuaaConfig, validateJKU validation.JKUValidationFunc, configCache *cache.Cache) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {

		uuaDomain := xsuaaConfig.UaaDomain
		jkuUrl := token.Header["jku"].(string)
		tokenUrl := jkuUrl

		if jkuUrl == "" {
			return nil, errors.New("no jku in header available to validate trust")
		}

		// check if jku url corresponds to xsuaa url been bound to the app
		if isValid, err := validateJKU(jkuUrl, uuaDomain); !isValid && err != nil {
			return nil, err
		}

		keyID, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("expecting JWT header to have string kid")
		}

		// multiple keys mights be used based on domain etc - unusual, but technically possible
		cacheKey := "jwks_" + uuaDomain + "_" + keyID

		jwks, found := configCache.Get(cacheKey)
		if !found {
			var err error
			jwks, err = jwk.Fetch(context.Background(), tokenUrl)
			if err != nil {
				return nil, fmt.Errorf("can't fetch public JWKS")
			}
			configCache.Set(cacheKey, jwks, cache.DefaultExpiration)
		}

		if key, ok := jwks.(jwk.Set).LookupKeyID(keyID); ok {
			var rawKey interface{}
			if err := key.Raw(&rawKey); err != nil {
				return nil, err
			} else {
				return rawKey, nil
			}
		}

		return nil, fmt.Errorf("unable to find key %q", keyID)
	}
}