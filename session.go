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
		"id":	  user.id,
		"name":   user.name,
		"email":  user.email,
		"roles":  strings.Join(user.roles, ","),
	}).Debugf("found the user identity: %s in the request", user.email)

	return user, nil
}

//
// refreshIdentity refreshes the access token for the user
//
func (r keycloakProxy) refreshIdentity(cx *gin.Context) (*userContext, error) {
	// step: attempt to the retrieve the access toke, either from the store or from cookie
	var state *refreshState
	var err error

	if r.store != nil {
		state, err = r.Get()
	}

	// step: check if the offline session has expired
	if time.Now().After(state.expireOn) {
		log.Warningf("failed to refresh the access token, the refresh token has expired, expiration: %s", state.expireOn)
		return jose.JWT{}, ErrAccessTokenExpired
	}

	// step: attempts to refresh the access token
	token, expires, err := r.refreshToken(state.refreshToken)
	if err != nil {
		// step: has the refresh token expired
		switch err {
		case ErrRefreshTokenExpired:
			log.WithFields(log.Fields{"token": token}).Warningf("the refresh token has expired")
			clearSessionState(cx)
		default:
			log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to refresh the access token")
		}

		return jose.JWT{}, err
	}

	// step: inject the refreshed access token
	log.WithFields(log.Fields{
		"access_expires_in":  expires.Sub(time.Now()).String(),
		"refresh_expires_in": state.expireOn.Sub(time.Now()).String(),
	}).Infof("injecting refreshed access token, expires on: %s", expires.Format(time.RFC1123))

	// step: create the session
	return token, r.createSession(token, expires, cx)
}

//
// getSessionState retrieves the session state from the request
//
func (r *keycloakProxy) getSessionState(cx *gin.Context) (*refreshState, error) {
	// step: find the session data cookie
	cookie := findCookie(sessionStateCookieName, cx.Request.Cookies())
	if cookie == nil {
		return nil, ErrNoCookieFound
	}

	return decryptStateSession(cookie.Value, r.config.EncryptionKey)
}

//
// createSession creates a session cookie with the access token
//
func (r *keycloakProxy) createSession(token jose.JWT, expires time.Time, cx *gin.Context) error {
	http.SetCookie(cx.Writer, createSessionCookie(token.Encode(), cx.Request.Host, expires.Add(time.Duration(5)*time.Minute)))

	return nil
}

//
// createSessionState creates a session state cookie, used to hold the refresh cookie and the expiration time
//
func (r *keycloakProxy) createSessionState(state *refreshState, cx *gin.Context) error {
	// step: we need to encode the state
	encoded, err := encryptStateSession(state, r.config.EncryptionKey)
	if err != nil {
		return err
	}
	// step: create a session state cookie
	http.SetCookie(cx.Writer, createSessionStateCookie(encoded, cx.Request.Host, state.expireOn))

	return nil
}

//
// encryptStateSession encodes the session state information into a value for a cookie to consume
//
func encryptStateSession(session *refreshState, key string) (string, error) {
	// step: encode the session into a string
	encoded := fmt.Sprintf("%d|%s", session.expireOn.Unix(), session.refreshToken)

	// step: encrypt the cookie
	cipherText, err := encryptDataBlock([]byte(encoded), []byte(key))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

//
// decryptStateSession decodes the session state cookie value
//
func decryptStateSession(state, key string) (*refreshState, error) {
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

	return &refreshState{
		expireOn:     expiration,
		refreshToken: sections[1],
	}, nil
}

//
// createSessionCookie creates a new session cookie
//
func createSessionCookie(token, hostname string) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Domain:   strings.Split(hostname, ":")[0],
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		Value:    token,
	}
}

//
// createSessionStateCookie creates a new session state cookie
//
func createSessionStateCookie(token, hostname string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     sessionStateCookieName,
		Domain:   strings.Split(hostname, ":")[0],
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		Value: token,
	}
}

//
// clearSessionState clears the session cookie
//
func clearSessionState(cx *gin.Context) {
	http.SetCookie(cx.Writer, createSessionStateCookie("", cx.Request.Host, time.Now()))
}

//
// clearSession clears the session cookie
//
func clearSession(cx *gin.Context) {
	http.SetCookie(cx.Writer, createSessionCookie("", cx.Request.Host, time.Now()))
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

