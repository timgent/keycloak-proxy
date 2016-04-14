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
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oidc"
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
// getSessionState retrieves the session state from the request
//
func (r *keycloakProxy) getRefreshSession(cx *gin.Context, user *userContext) (*refreshSession, error) {
	var session string

	// step: are we using a store to hold the refresh token?
	if r.store != nil {
		v, err := r.Get(user.token.Data())
		if err != nil {
			return nil, err
		}
		session = v
	} else {
		// step: find the session data cookie
		cookie := findCookie(sessionStateCookieName, cx.Request.Cookies())
		if cookie == nil {
			return nil, ErrNoCookieFound
		}
	}

	// step: decrypt the refresh session
	return decryptRefreshSession(session, r.config.EncryptionKey)
}

//
// dropSessionCookie creates a session cookie with the access token
//
func dropSessionCookie(cx *gin.Context, token jose.JWT) error {
	http.SetCookie(cx.Writer, createSessionCookie(token.Encode(), cx.Request.Host, nil))

	return nil
}

//
// dropRefreshCookie drops an encrypted refresh session cookie into the request
//
func dropRefreshCookie(cx *gin.Context, state *refreshSession, key string) error {
	// step: we need to encode the state
	encoded, err := encryptStateSession(state, key)
	if err != nil {
		return err
	}

	// step: create a session state cookie
	http.SetCookie(cx.Writer, createSessionRefreshCookie(encoded, cx.Request.Host, &state.expireOn))

	return nil
}

//
// clearAllCookies is just a helper function for the below
//
func clearAllCookies(cx *gin.Context) {
	clearSessionCookie(cx)
	clearRefreshSessionCookie(cx)
}

//
// clearRefreshSessionCookie clears the session cookie
//
func clearRefreshSessionCookie(cx *gin.Context) {
	http.SetCookie(cx.Writer, createSessionRefreshCookie("", cx.Request.Host, &time.Now()))
}

//
// clearSessionCookie clears the session cookie
//
func clearSessionCookie(cx *gin.Context) {
	http.SetCookie(cx.Writer, createSessionCookie("", cx.Request.Host, &time.Now()))
}

//
// encryptStateSession encodes the session state information into a value for a cookie to consume
//
func encryptStateSession(session *refreshSession, key string) (string, error) {
	// step: encode the session into a string
	encoded := fmt.Sprintf("%d|%s", session.expireOn.Unix(), session.token)

	// step: encrypt the cookie
	cipherText, err := encryptDataBlock([]byte(encoded), []byte(key))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

//
// decryptRefreshSession decodes the session state cookie value
//
func decryptRefreshSession(state, key string) (*refreshSession, error) {
	// step: decode the base64 encrypted cookie
	cipherText, err := base64.StdEncoding.DecodeString(state)
	if err != nil {
		return nil, err
	}

	// step: decrypt the cookie back in the expiration|token
	plainText, err := decryptDataBlock(cipherText, []byte(key))
	if err != nil {
		return nil, ErrInvalidSession
	}

	// step: extracts the sections from the state
	sections := strings.Split(string(plainText), "|")
	if len(sections) != 2 {
		return nil, ErrInvalidSession
	}

	// step: convert the unit timestamp
	expiration, err := convertUnixTime(sections[0])
	if err != nil {
		return nil, ErrInvalidSession
	}

	return &refreshSession{
		expireOn: expiration,
		token:    sections[1],
	}, nil
}

//
// createSessionCookie creates a new session cookie
//
func createSessionCookie(token, hostname string, expires *time.Time) *http.Cookie {
	cookie := http.Cookie{
		Name:     sessionCookieName,
		Domain:   strings.Split(hostname, ":")[0],
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		Value:    token,
	}

	if expires == nil {
		cookie.Expires = expires
	}

	return cookie
}

//
// createSessionRefreshCookie creates a new session state cookie
//
func createSessionRefreshCookie(token, hostname string, expires *time.Time) *http.Cookie {
	cookie := http.Cookie{
		Name:     sessionStateCookieName,
		Domain:   strings.Split(hostname, ":")[0],
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		Value:    token,
	}
	if expires != nil {
		cookie.Expires = expires
	}

	return cookie
}

//
// getTokenFromBearer attempt to retrieve token from bearer token
//
func getTokenFromBearer(cx *gin.Context) (jose.JWT, error) {
	authz := cx.Request.Header.Get(authorizationHeader)
	if authz == "" {
		return jose.JWT{}, ErrSessionNotFound
	}

	items := strings.Split(authz, " ")
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
	cookie := findCookie(sessionCookieName, cx.Request.Cookies())
	if cookie == nil {
		return jose.JWT{}, ErrSessionNotFound
	}

	return jose.ParseJWT(cookie.Value)
}

//
// extractIdentity parse the jwt token and extracts the various elements is order to construct
//
func extractIdentity(token jose.JWT) (*userContext, error) {
	// step: decode the claims from the tokens
	claims, err := token.Claims()
	if err != nil {
		return nil, err
	}
	// step: extract the identity
	identity, err := oidc.IdentityFromClaims(claims)
	if err != nil {
		return nil, err
	}
	// step: ensure we have and can extract the preferred name of the user, if not, we set to the ID
	preferredName, found, err := claims.StringClaim(claimPreferredName)
	if err != nil || !found {
		// choice: set the preferredName to the Email if claim not found
		preferredName = identity.Email
	}
	// step: retrieve the audience from access token
	audience, found, err := claims.StringClaim(claimAudience)
	if err != nil || !found {
		return nil, fmt.Errorf("the access token does not container a audience claim")
	}
	var list []string

	// step: extract the realm roles
	if realmRoles, found := claims[claimRealmAccess].(map[string]interface{}); found {
		if roles, found := realmRoles[claimResourceRoles]; found {
			for _, r := range roles.([]interface{}) {
				list = append(list, fmt.Sprintf("%s", r))
			}
		}
	}
	// step: extract the roles from the access token
	if accesses, found := claims[claimResourceAccess].(map[string]interface{}); found {
		for roleName, roleList := range accesses {
			scopes := roleList.(map[string]interface{})
			if roles, found := scopes[claimResourceRoles]; found {
				for _, r := range roles.([]interface{}) {
					list = append(list, fmt.Sprintf("%s:%s", roleName, r))
				}
			}
		}
	}

	return &userContext{
		id:            identity.ID,
		name:          preferredName,
		audience:      audience,
		preferredName: preferredName,
		email:         identity.Email,
		expiresAt:     identity.ExpiresAt,
		roles:         list,
		token:         token,
		claims:        claims,
	}, nil
}
