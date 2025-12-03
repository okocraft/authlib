package jwtclaims

import (
	"errors"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v5"
)

type RefreshTokenClaims struct {
	BaseClaims

	LoginID uuid.UUID
}

func (c RefreshTokenClaims) CreateJWTClaims() jwt.Claims {
	claims := jwt.MapClaims{}

	c.SaveBaseClaimsTo(claims)

	claims["login_id"] = c.LoginID.String()

	return claims
}

func (c RefreshTokenClaims) Validate(now time.Time) error {
	if err := c.BaseClaims.Validate(now); err != nil {
		return err
	}

	if c.LoginID.IsNil() {
		return errors.New("missing login_id claim")
	}

	return nil
}

func ReadRefreshTokenClaimsFrom(claims jwt.MapClaims) (RefreshTokenClaims, error) {
	base, err := ReadBaseClaimsFrom(claims)
	if err != nil {
		return RefreshTokenClaims{}, err
	}

	ret := RefreshTokenClaims{
		BaseClaims: base,
	}

	rawLoginID, ok := claims["login_id"].(string)
	if !ok {
		return RefreshTokenClaims{}, errors.New("missing login_id claim")
	}
	loginID, err := uuid.FromString(rawLoginID)
	if err != nil {
		return RefreshTokenClaims{}, err
	}
	ret.LoginID = loginID

	return ret, nil
}
