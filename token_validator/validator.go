package token_validator

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

type TokenType string

type OpenIdConfig struct {
	JwksUri string `json:"jwks_uri"`
}

type Jwk struct {
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type KeysConfig struct {
	Keys []Jwk `json:"keys"`
}

const (
	TokenTypeIdToken     TokenType = "id_token"
	TokenTypeAccessToken TokenType = "access_token"
)

// return true if token is valid
func (c *Client) ValidateToken(token string, tokenType TokenType) (bool, error) {
	// parse token unverified
	jwtToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return false, err
	}

	jwk, err := c.getJwk(jwtToken)
	if err != nil {
		return false, err
	}

	publicKey, err := getPublicKeyFromJwk(jwk)
	if err != nil {
		return false, err
	}

	parserOptions := []jwt.ParserOption{
		jwt.WithAudience(c.config.ApplicationId),
		jwt.WithExpirationRequired(),
	}

	keyFunc := func(t *jwt.Token) (interface{}, error) {
		return publicKey, nil
	}

	jwtToken, err = jwt.Parse(token, keyFunc, parserOptions...)
	if err != nil {
		return false, err
	}

	if !jwtToken.Valid {
		return false, errors.New("token is invalid")
	}

	// verify claims
	isValidClaims := c.verifyTokenClaims(jwtToken)

	return isValidClaims, nil
}

func (c *Client) verifyTokenClaims(token *jwt.Token) bool {
	claims := token.Claims.(jwt.MapClaims)

	return (claims["tid"].(string) == c.config.TenantId)
}

func (c *Client) getJwk(token *jwt.Token) (*Jwk, error) {
	keyConfigs, err := c.getKeysConfig()
	if err != nil {
		return nil, err
	}

	kid := token.Header["kid"].(string)

	for _, key := range keyConfigs.Keys {
		if key.Kid == kid {
			return &key, nil
		}
	}
	return nil, errors.New("could not find kid")
}

func (c *Client) getKeysConfig() (*KeysConfig, error) {
	uri := fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys?appid=%s", c.config.TenantId, c.config.ApplicationId)

	resp, err := http.Get(uri)
	if err != nil {
		return nil, err
	}

	responseData, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	config := &KeysConfig{}
	err = json.Unmarshal(responseData, &config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// add fallback to use common keys in future
// func getOpenIdConfig() (*OpenIdConfig, error) {
// 	resp, err := http.Get("https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration")
// 	if err != nil {
// 		return nil, err
// 	}

// 	responseData, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	config := &OpenIdConfig{}
// 	err = json.Unmarshal(responseData, &config)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return config, nil
// }

// func getKeysConfig() (*KeysConfig, error) {
// 	openIdConfig, err := getOpenIdConfig()
// 	if err != nil {
// 		return nil, err
// 	}

// 	resp, err := http.Get(openIdConfig.JwksUri)
// 	if err != nil {
// 		return nil, err
// 	}

// 	responseData, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	config := &KeysConfig{}
// 	err = json.Unmarshal(responseData, &config)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return config, nil
// }

// func rsaPemFromJwk(jwk *Keys) string {
// }
