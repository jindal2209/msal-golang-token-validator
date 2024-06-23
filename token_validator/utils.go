package token_validator

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

func getPublicKeyFromJwk(jwk *Jwk) (*rsa.PublicKey, error) {
	// decode the base64 bytes for n
	nb, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}

	// decode the base64 bytes for e
	eb, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}

	pub := rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: int(new(big.Int).SetBytes(eb).Uint64()),
	}

	return &pub, nil
}
