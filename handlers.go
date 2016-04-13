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
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-oidc/oauth2"
	"github.com/gin-gonic/gin"
	"github.com/unrolled/secure"
)

//
// The logic is broken into four handlers just to simplify the code
//
//  a) entryPointHandler checks if the the uri requires authentication
//  b) authenticationHandler verifies the access token
//  c) admissionHandler verifies that the token is authorized to access to uri resource
//  c) proxyHandler is responsible for handling the reverse proxy to the upstream endpoint
//

const (
	// cxEnforce is the tag name for a request requiring
	cxEnforce = "Enforcing"
)

//
// loggingHandler is a custom http logger
//
func (r *keycloakProxy) loggingHandler() gin.HandlerFunc {
	return func(cx *gin.Context) {
		start := time.Now()
		cx.Next()
		latency := time.Now().Sub(start)

		log.WithFields(log.Fields{
			"client_ip": cx.ClientIP(),
			"method":    cx.Request.Method,
			"status":    cx.Writer.Status(),
			"bytes":     cx.Writer.Size(),
			"path":      cx.Request.URL.Path,
			"latency":   latency.String(),
		}).Infof("[%d] |%s| |%10v| %-5s %s", cx.Writer.Status(), cx.ClientIP(), latency, cx.Request.Method, cx.Request.URL.Path)
	}
}

//
// securityHandler performs numerous security checks on the request
//
func (r *keycloakProxy) securityHandler() gin.HandlerFunc {
	// step: create the security options
	secure := secure.New(secure.Options{
		AllowedHosts:         r.config.Hostnames,
		BrowserXssFilter:     true,
		ContentTypeNosniff:   true,
		FrameDeny:            true,
		STSIncludeSubdomains: true,
		STSSeconds:           31536000,
	})

	return func(cx *gin.Context) {
		// step: pass through the security middleware
		if err := secure.Process(cx.Writer, cx.Request); err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed security middleware")
			cx.Abort()
			return
		}
		// step: permit the request to continue
		cx.Next()
	}
}

//
// entryPointHandler checks to see if the request requires authentication
//
func (r *keycloakProxy) entryPointHandler() gin.HandlerFunc {
	return func(cx *gin.Context) {
		if strings.HasPrefix(cx.Request.URL.Path, oauthURL) {
			cx.Next()
			return
		}

		// step: check if authentication is required - gin doesn't support wildcard url, so we have have to use prefixes
		for _, resource := range r.config.Resources {
			if strings.HasPrefix(cx.Request.URL.Path, resource.URL) {
				// step: has the resource been white listed?
				if resource.WhiteListed {
					break
				}
				// step: inject the resource into the context, saves us from doing this again
				if containedIn(cx.Request.Method, resource.Methods) || containedIn("ANY", resource.Methods) {
					cx.Set(cxEnforce, resource)
				}
				break
			}
		}
		// step: pass into the authentication and admission handlers
		cx.Next()

		// step: add a custom headers to the request
		for k, v := range r.config.Header {
			cx.Request.Header.Set(k, v)
		}

		// step: check the request has not been aborted and if not, proxy request
		if !cx.IsAborted() {
			r.proxyHandler(cx)
		}
	}
}

//
// authenticationHandler is responsible for verifying the access token
//
//  steps:
//  - check if the request is protected and requires validation
//  - retrieve the access token from the cookie or authorization header, if there isn't a token, check
//    if there is a session state and use the refresh token to refresh access token
//  - extract the user context from the access token, ensuring the minimum claims
//  - validate the audience of the access token is directed to us
//  - inject the user context into the request context for later layers
//  - skip verification of the access token if enabled
//  - else we validate the access token against the keypair via openid client
//  - if everything is cool, move on, else thrown a redirect or forbidden
//
func (r *keycloakProxy) authenticationHandler() gin.HandlerFunc {
	return func(cx *gin.Context) {
		// step: is authentication required on this uri?
		if _, found := cx.Get(cxEnforce); !found {
			log.Debugf("skipping the authentication handler, resource not protected")
			cx.Next()
			return
		}

		user, err := getIdentity(cx)
		if err != nil {
			// choice: if no access token but refresh tokens is set, attempt to refresh access token
			if err == ErrSessionNotFound && !r.config.RefreshSessions {
				user, err = r.refreshIdentity(cx)
				if err != nil {
					log.WithFields(log.Fields{
						"error": err.Error(),
					}).Errorf("failed to refresh the access token")

					r.redirectToAuthorization(cx)
					return
				}
			} else {
				log.WithFields(log.Fields{
					"error": err.Error(),
				}).Errorf("failed to get session, redirecting for authorization")

				r.redirectToAuthorization(cx)
				return
			}
		}
		// step: inject the user into the context
		cx.Set(userContextName, user)

		// step: check the audience for the token is us
		if !user.isAudience(r.config.ClientID) {
			log.WithFields(log.Fields{
				"username":   user.name,
				"expired_on": user.expiresAt.String(),
				"issued":     user.audience,
				"clientid":   r.config.ClientID,
			}).Warnf("the access token audience is not us, redirecting back for authentication")

			r.redirectToAuthorization(cx)
			return
		}

		// step: verify the access token
		if r.config.SkipTokenVerification {
			log.Warnf("token verification enabled, skipping verification process - FOR TESTING ONLY")
			if user.isExpired() {
				log.WithFields(log.Fields{
					"username":   user.name,
					"expired_on": user.expiresAt.String(),
				}).Errorf("the session has expired and verification switch off")

				r.redirectToAuthorization(cx)
			}

			return
		}

		// step: verify the access token
		if err := r.verifyToken(user.token); err != nil {
			fields := log.Fields{
				"username":   user.name,
				"expired_on": user.expiresAt.String(),
				"error":      err.Error(),
			}

			// step: if the error post verification is anything other than a token expired error
			// we immediately throw an access forbidden - as there is something messed up in the token
			if err != ErrAccessTokenExpired {
				log.WithFields(log.Fields{"error": err.Error()}).Errorf("access token has expired")
				r.accessForbidden(cx)
				return
			}
			if user.isBearerToken() {
				log.WithFields(fields).Errorf("the session has expired and we are using bearer token")
				r.redirectToAuthorization(cx)
				return
			}
			// step: are we refreshing the access tokens?
			if !r.config.RefreshSessions {
				log.WithFields(fields).Errorf("the session has expired and token refreshing is disabled")
				r.redirectToAuthorization(cx)
				return
			}
			// step: attempt to refresh the access token
			user, err := r.refreshIdentity(cx)
			if err != nil {
				log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to refresh the access token")
				r.redirectToAuthorization(cx)
				return
			}
			// step: inject the user into the context
			cx.Set(userContextName, user)
		}

		cx.Next()
	}
}

//
// admissionHandler is responsible checking the access token against the protected resource
//
// steps:
//  - check if authentication and validation is required
//  - if so, retrieve the resource and user from the request context
//  - if we have any roles requirements validate the roles exists in the access token
//  - if er have any claim requirements validate the claims are the same
//  - if everything is ok, we permit the request to pass through
//
func (r *keycloakProxy) admissionHandler() gin.HandlerFunc {
	// step: compile the regex's for the claims
	claimMatches := make(map[string]*regexp.Regexp, 0)
	for k, v := range r.config.ClaimsMatch {
		claimMatches[k] = regexp.MustCompile(v)
	}

	return func(cx *gin.Context) {
		// step: if authentication is required on this, grab the resource spec
		ur, found := cx.Get(cxEnforce)
		if !found {
			return
		}

		// step: grab the identity from the context
		uc, found := cx.Get(userContextName)
		if !found {
			panic("there is no identity in the request context")
		}

		resource := ur.(*Resource)
		identity := uc.(*userContext)

		// step: we need to check the roles
		if roles := len(resource.Roles); roles > 0 {
			if !hasRoles(resource.Roles, identity.roles) {
				log.WithFields(log.Fields{
					"access":   "denied",
					"username": identity.name,
					"resource": resource.URL,
					"required": resource.getRoles(),
				}).Warnf("access denied, invalid roles")
				r.accessForbidden(cx)

				return
			}
		}
		// step: if we have any claim matching, validate the tokens has the claims
		for claimName, match := range claimMatches {
			// step: if the claim is NOT in the token, we access deny
			value, found, err := identity.claims.StringClaim(claimName)
			if err != nil {
				log.WithFields(log.Fields{
					"access":   "denied",
					"username": identity.name,
					"resource": resource.URL,
					"error":    err.Error(),
				}).Errorf("unable to extract the claim from token")

				r.accessForbidden(cx)

				return
			}

			if !found {
				log.WithFields(log.Fields{
					"access":   "denied",
					"username": identity.name,
					"resource": resource.URL,
					"claim":    claimName,
				}).Warnf("the token does not have the claim")

				r.accessForbidden(cx)

				return
			}

			// step: check the claim is the same
			if !match.MatchString(value) {
				log.WithFields(log.Fields{
					"access":   "denied",
					"username": identity.name,
					"resource": resource.URL,
					"claim":    claimName,
					"issued":   value,
					"required": match,
				}).Warnf("the token claims does not match claim requirement")

				r.accessForbidden(cx)

				return
			}
		}

		log.WithFields(log.Fields{
			"access":   "permitted",
			"username": identity.name,
			"resource": resource.URL,
			"expires":  identity.expiresAt.Sub(time.Now()).String(),
		}).Debugf("resource access permitted: %s", cx.Request.RequestURI)
	}
}

//
// proxyHandler is responsible to proxy the requests on to the upstream endpoint
//
func (r *keycloakProxy) proxyHandler(cx *gin.Context) {
	// step: double check, if enforce is true and no user context it's a internal error
	if _, found := cx.Get(cxEnforce); found {
		if _, found := cx.Get(userContextName); !found {
			log.Errorf("no user context found for a secure request")
			cx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
	}

	// step: retrieve the user context if any
	if identity, found := cx.Get(userContextName); found {
		id := identity.(*userContext)
		cx.Request.Header.Add("X-Auth-UserId", id.id)
		cx.Request.Header.Add("X-Auth-Subject", id.preferredName)
		cx.Request.Header.Add("X-Auth-Username", id.name)
		cx.Request.Header.Add("X-Auth-Email", id.email)
		cx.Request.Header.Add("X-Auth-ExpiresIn", id.expiresAt.String())
		cx.Request.Header.Add("X-Auth-Token", id.token.Encode())
		cx.Request.Header.Add("X-Auth-Roles", strings.Join(id.roles, ","))
	}

	// step: add the default headers
	cx.Request.Header.Add("X-Forwarded-For", cx.Request.RemoteAddr)
	cx.Request.Header.Set("X-Forwarded-Agent", prog)
	cx.Request.Header.Set("X-Forwarded-Agent-Version", version)

	// step: is this connection upgrading?
	if isUpgradedConnection(cx.Request) {
		log.Debugf("upgrading the connnection to %s", cx.Request.Header.Get(headerUpgrade))
		if err := r.tryUpdateConnection(cx); err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to upgrade the connection")

			cx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		cx.Abort()

		return
	}

	r.upstream.ServeHTTP(cx.Writer, cx.Request)
}

// ---
// The handlers for managing the OAuth authentication flow
// ---

//
// oauthAuthorizationHandler is responsible for performing the redirection to keycloak service
//
func (r *keycloakProxy) oauthAuthorizationHandler(cx *gin.Context) {
	// step: is token verification switched on?
	if r.config.SkipTokenVerification {
		r.accessForbidden(cx)
		return
	}
	// step: grab the oauth client
	oac, err := r.client.OAuthClient()
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Errorf("failed to retrieve the oauth client")
		cx.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// step: set the access type of the session
	accessType := ""
	if r.config.RefreshSessions {
		accessType = "offline"
	}

	log.WithFields(log.Fields{
		"client_ip":   cx.ClientIP(),
		"access_type": accessType,
	}).Infof("incoming authorization request from client address: %s", cx.ClientIP())

	// step: build the redirection url to the authentication server
	redirectionURL := oac.AuthCodeURL(cx.Query("state"), accessType, "")

	// step: if we have a custom sign in page, lets display that
	if r.config.hasSignInPage() {
		// step: add the redirection url
		model := make(map[string]string, 0)
		for k, v := range r.config.TagData {
			model[k] = v
		}
		model["redirect"] = redirectionURL

		cx.HTML(http.StatusOK, path.Base(r.config.SignInPage), model)
		return
	}
	// step: send a redirect to the client
	r.redirectToURL(redirectionURL, cx)
}

//
// oauthCallbackHandler is responsible for handling the response from keycloak
//
func (r *keycloakProxy) oauthCallbackHandler(cx *gin.Context) {
	// step: get the code and state
	code  := cx.Request.URL.Query().Get("code")
	state := cx.Request.URL.Query().Get("state")

	// step: is token verification switched on?
	if r.config.SkipTokenVerification {
		r.accessForbidden(cx)
		return
	}
	// step: ensure we have a authorization code to exchange
	if code == "" {
		log.WithFields(log.Fields{"client_ip": cx.ClientIP()}).Error("code parameter missing in callback")
		r.accessForbidden(cx)

		return
	}
	// step: ensure we have a state or default to root /
	if state == "" {
		state = "/"
	}

	// step: exchange the authorization for a access token
	response, err := r.getToken(oauth2.GrantTypeAuthCode, code)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Errorf("unable to exchange code for access token")
		r.accessForbidden(cx)
		return
	}

	// step: parse decode the identity token
	token, identity, err := parseToken(response.IDToken)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Errorf("unable to parse id token for identity")
		r.accessForbidden(cx)
		return
	}
	// step: verify the token is valid
	if err := r.verifyToken(token); err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Errorf("unable to verify the id token")
		r.accessForbidden(cx)
		return
	}

	// step: attempt to decode the access token?
	ac, id, err := parseToken(response.AccessToken)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Errorf("unable to parse the access token, using id token only")
	} else {
		token = ac
		identity = id
	}

	log.WithFields(log.Fields{
		"email":   identity.Email,
		"expires": identity.ExpiresAt,
	}).Infof("issuing a user session")

	// step: create a session from the access token
	if err := r.createSession(token, identity.ExpiresAt, cx); err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to inject the session token")
		cx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	// step: are we using refresh tokens?
	if r.config.RefreshSessions {
		// step: create the state session
		state := &refreshState{
			refreshToken: response.RefreshToken,
			expireOn:     time.Now().Add(r.config.MaxSession),
		}

		// step: can we parse and extract the refresh token from the response
		// - note, the refresh token can be custom, i.e. doesn't have to be a jwt i.e. google for example
		_, refreshToken, err := parseToken(response.RefreshToken)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
			}).Errorf("unable to parse refresh token (unknown format) using the as a static string")
		} else {
			// step: set the expiration of the refresh token.
			// - first we check if the duration exceeds the expiration of the refresh token
			if state.expireOn.After(refreshToken.ExpiresAt) {
				log.WithFields(log.Fields{
					"email":       refreshToken.Email,
					"max_session": r.config.MaxSession.String(),
					"duration":    state.expireOn.Format(time.RFC1123),
					"refresh":     refreshToken.ExpiresAt.Format(time.RFC1123),
				}).Errorf("max session exceeds the expiration of the refresh token, defaulting to refresh token")
				state.expireOn = refreshToken.ExpiresAt
			}
		}
		// step: create and inject the state session
		if err := r.createSessionState(state, cx); err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to inject the session state into request")

			cx.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		// step: some debugging is useful here
		log.WithFields(log.Fields{
			"email":      identity.Email,
			"client_ip":  cx.ClientIP(),
			"expires_in": state.expireOn.Sub(time.Now()).String(),
		}).Infof("successfully retrieve refresh token for client: %s", identity.Email)
	}

	r.redirectToURL(state, cx)
}

//
// expirationHandler checks if the token has expired
//
func (r *keycloakProxy) expirationHandler(cx *gin.Context) {
	// step: get the access token from the request
	user, err := getIdentity(cx)
	if err != nil {
		cx.AbortWithError(http.StatusUnauthorized, err)
		return
	}
	// step: check the access is not expired
	if user.isExpired() {
		cx.AbortWithError(http.StatusUnauthorized, err)
		return
	}

	cx.AbortWithStatus(http.StatusOK)
}

//
// tokenHandler display access token to screen
//
func (r *keycloakProxy) tokenHandler(cx *gin.Context) {
	// step: extract the access token from the request
	user, err := getIdentity(cx)
	if err != nil {
		cx.AbortWithError(http.StatusBadRequest, fmt.Errorf("unable to retrieve session, error: %s", err))
		return
	}
	// step: write the json content
	cx.Writer.Header().Set("Content-Type", "application/json")
	cx.String(http.StatusOK, fmt.Sprintf("%s", user.token.Payload))
}

//
// healthHandler is a health check handler for the service
//
func (r *keycloakProxy) healthHandler(cx *gin.Context) {
	cx.String(http.StatusOK, "OK")
}
