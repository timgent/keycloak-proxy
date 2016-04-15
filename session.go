/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-oidc/jose"
	"github.com/gin-gonic/gin"
)

const (
	claimPreferredName  = "preferred_username"
	claimAudience       = "aud"
	claimResourceAccess = "resource_access"
	claimRealmAccess    = "realm_access"
	claimResourceRoles  = "roles"
)

//
// getRefreshFromRequest retrieves the session state from the request
//
func (r *keycloakProxy) getRefreshFromRequest(cx *gin.Context, user *userContext) (*RefreshToken, error) {
	var encoded string

	// step: are we using a store to hold the refresh token?
	if r.store != nil {
		v, err := r.GetRefreshToken(&user.token)
		if err != nil {
			return nil, err
		}
		encoded = v
	} else {
		// step: find the session data cookie
		cookie := findCookie(cookieRefreshToken, cx.Request.Cookies())
		if cookie == nil {
			return nil, ErrNoSessionStateFound
		}
	}

	// step: decrypt the refresh token
	refresh, err := decryptRefreshToken(encoded, r.config.EncryptionKey)
	if err != nil {
		return nil, err
	}

	// step: decode and return refresh token
	return refresh, nil
}

//
// getIdentity retrieves the user identity from a request, either from a session cookie or a bearer token
//
func getIdentity(cx *gin.Context) (*userContext, error) {
	isBearer := false
	// step: check for a bearer token or cookie with jwt token
	token, err := getTokenFromCookie(cx)
	if err != nil {
		if err != ErrSessionNotFound {
			return nil, err
		}
		// step: else attempt to grab token from the bearer token]
		token, err = getTokenFromBearer(cx)
		if err != nil {
			return nil, err
		}
		isBearer = true
	}
	// step: parse the access token and extract the user identity
	user, err := extractIdentity(token)
	if err != nil {
		return nil, err
	}
	user.bearerToken = isBearer

	// step: add some logging
	log.WithFields(log.Fields{
		"id":    user.id,
		"name":  user.name,
		"email": user.email,
		"roles": strings.Join(user.roles, ","),
	}).Debugf("found the user identity: %s in the request", user.email)

	return user, nil
}

//
// dropCookie drops a cookie into the response
//
func dropCookie(cx *gin.Context, name, value string, expires time.Time) {
	cookie := &http.Cookie{
		Name:     name,
		Domain:   strings.Split(cx.Request.Host, ":")[0],
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		Value:    value,
	}
	if !expires.IsZero() {
		cookie.Expires = expires
	}

	http.SetCookie(cx.Writer, cookie)
}

func dropAccessTokenCookie(cx *gin.Context, token jose.JWT) {
	dropCookie(cx, cookieAccessToken, token.Encode(), time.Time{})
}

func dropRefreshTokenCookie(cx *gin.Context, token string, expires time.Time) {
	dropCookie(cx, cookieRefreshToken, token, expires)
}

//
// clearAllCookies is just a helper function for the below
//
func clearAllCookies(cx *gin.Context) {
	clearSessionCookie(cx)
	clearRefreshTokenCookie(cx)
}

//
// clearRefreshSessionCookie clears the session cookie
//
func clearRefreshTokenCookie(cx *gin.Context) {
	dropCookie(cx, cookieRefreshToken, "", time.Now())
}

//
// clearSessionCookie clears the session cookie
//
func clearSessionCookie(cx *gin.Context) {
	dropCookie(cx, cookieAccessToken, "", time.Now())
}

//
// encryptRefreshToken encodes the session state information into a value for a cookie to consume
//
func encryptRefreshToken(session *RefreshToken, key string) (string, error) {
	// step: encrypt the refresh state
	cipherText, err := encryptDataBlock([]byte(session.Encode()), []byte(key))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

//
// decryptRefreshToken decodes the session state cookie value
//
func decryptRefreshToken(state, key string) (*RefreshToken, error) {
	// step: decode the base64 encrypted cookie
	cipherText, err := base64.StdEncoding.DecodeString(state)
	if err != nil {
		return nil, err
	}

	// step: decrypt the cookie back in the expiration|token
	encoded, err := decryptDataBlock(cipherText, []byte(key))
	if err != nil {
		return nil, ErrInvalidSession
	}

	return newRefreshToken(string(encoded))
}

//
// getTokenFromBearer attempt to retrieve token from bearer token
//
func getTokenFromBearer(cx *gin.Context) (jose.JWT, error) {
	auth := cx.Request.Header.Get(authorizationHeader)
	if auth == "" {
		return jose.JWT{}, ErrSessionNotFound
	}

	items := strings.Split(auth, " ")
	if len(items) != 2 {
		return jose.JWT{}, ErrInvalidSession
	}

	return jose.ParseJWT(items[1])
}

//
// getTokenFromCookie attempt to grab token from cookie
//
func getTokenFromCookie(cx *gin.Context) (jose.JWT, error) {
	// step: find the authentication cookie from the request
	cookie := findCookie(cookieAccessToken, cx.Request.Cookies())
	if cookie == nil {
		return jose.JWT{}, ErrSessionNotFound
	}

	return jose.ParseJWT(cookie.Value)
}
