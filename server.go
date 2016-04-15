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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"crypto/sha256"
	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oidc"
	"github.com/gin-gonic/gin"
)

type keycloakProxy struct {
	// the proxy configuration
	config *Config
	// the gin service
	router *gin.Engine
	// the oidc client
	client *oidc.Client
	// the proxy client
	upstream reverseProxy
	// the upstream endpoint url
	endpoint *url.URL
	// the store interface
	store Store
}

type reverseProxy interface {
	ServeHTTP(rw http.ResponseWriter, req *http.Request)
}

func init() {
	// step: ensure all time is in UTC
	time.LoadLocation("UTC")
}

//
// newKeycloakProxy create's a new keycloak proxy from configuration
//
func newKeycloakProxy(cfg *Config) (*keycloakProxy, error) {
	var err error

	log.Infof("starting %s, version: %s, author: %s", prog, version, author)

	// step: set the logging level
	if cfg.LogJSONFormat {
		log.SetFormatter(&log.JSONFormatter{})
	}
	if cfg.Verbose {
		log.SetLevel(log.DebugLevel)
	}

	// step: create a proxy service
	service := &keycloakProxy{config: cfg}
	// step: parse the upstream endpoint
	service.endpoint, err = url.Parse(cfg.Upstream)
	if err != nil {
		return nil, err
	}
	// step: initialize the store if any
	if cfg.RefreshSessions && cfg.StoreURL != "" {
		if service.store, err = newStore(cfg.StoreURL); err != nil {
			return nil, err
		}
	}

	// step: initialize the reverse http proxy
	service.upstream, err = service.setupReverseProxy(service.endpoint)
	if err != nil {
		return nil, err
	}

	// step: initialize the openid client
	if cfg.SkipTokenVerification {
		log.Infof("TESTING ONLY CONFIG - the verification of the token have been disabled")

	} else {
		client, _, err := initializeOpenID(cfg.DiscoveryURL, cfg.ClientID, cfg.Secret, cfg.RedirectionURL, cfg.Scopes)
		if err != nil {
			return nil, err
		}
		service.client = client
	}

	// step: initialize the gin router
	service.router = gin.New()

	// step: load the templates
	if err = service.setupTemplates(); err != nil {
		return nil, err
	}
	// step: setup the gin router and add router
	if err := service.setupRouter(); err != nil {
		return nil, err
	}
	// step: display the protected resources
	for _, resource := range cfg.Resources {
		log.Infof("protecting resources under uri: %s", resource)
	}
	for name, value := range cfg.ClaimsMatch {
		log.Infof("the token must container the claim: %s, required: %s", name, value)
	}

	return service, nil
}

//
// Run starts the proxy service
//
func (r *keycloakProxy) Run() error {
	tlsConfig := &tls.Config{}

	// step: are we doing mutual tls?
	if r.config.TLSCaCertificate != "" {
		log.Infof("enabling mutual tls, reading in the ca: %s", r.config.TLSCaCertificate)

		caCert, err := ioutil.ReadFile(r.config.TLSCaCertificate)
		if err != nil {
			return err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	go func() {
		log.Infof("keycloak proxy service starting on %s", r.config.Listen)

		var err error
		if r.config.TLSCertificate == "" {
			err = r.router.Run(r.config.Listen)
		} else {
			server := &http.Server{
				Addr:      r.config.Listen,
				Handler:   r.router,
				TLSConfig: tlsConfig,
			}
			err = server.ListenAndServeTLS(r.config.TLSCertificate, r.config.TLSPrivateKey)
		}
		if err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Fatalf("failed to start the service")
		}
	}()

	return nil
}

//
// redirectToURL redirects the user and aborts the context
//
func (r keycloakProxy) redirectToURL(url string, cx *gin.Context) {
	// step: add the cors headers
	r.injectCORSHeaders(cx)

	cx.Redirect(http.StatusTemporaryRedirect, url)
	cx.Abort()
}

//
// accessForbidden redirects the user to the forbidden page
//
func (r keycloakProxy) accessForbidden(cx *gin.Context) {
	// step: do we have a custom forbidden page
	if r.config.hasForbiddenPage() {
		cx.HTML(http.StatusForbidden, path.Base(r.config.ForbiddenPage), r.config.TagData)
		cx.Abort()
		return
	}

	cx.AbortWithStatus(http.StatusForbidden)
}

//
// redirectToAuthorization redirects the user to authorization handler
//
func (r keycloakProxy) redirectToAuthorization(cx *gin.Context) {
	// step: are we handling redirects?
	if r.config.NoRedirects {
		cx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// step: add a state referrer to the authorization page
	authQuery := fmt.Sprintf("?state=%s", cx.Request.URL.String())

	// step: if verification is switched off, we can't authorization
	if r.config.SkipTokenVerification {
		log.Errorf("refusing to redirection to authorization endpoint, skip token verification switched on")
		cx.AbortWithStatus(http.StatusForbidden)
		return
	}

	r.redirectToURL(authorizationURL+authQuery, cx)
}

//
// injectCORSHeaders adds the cors access controls to the oauth responses
//
func (r *keycloakProxy) injectCORSHeaders(cx *gin.Context) {
	c := r.config.CORS
	if len(c.Origins) > 0 {
		cx.Writer.Header().Set("Access-Control-Allow-Origin", strings.Join(c.Origins, ","))
	}
	if len(c.Methods) > 0 {
		cx.Writer.Header().Set("Access-Control-Allow-Methods", strings.Join(c.Methods, ","))
	}
	if len(c.Headers) > 0 {
		cx.Writer.Header().Set("Access-Control-Allow-Headers", strings.Join(c.Headers, ","))
	}
	if len(c.ExposedHeaders) > 0 {
		cx.Writer.Header().Set("Access-Control-Expose-Headers", strings.Join(c.ExposedHeaders, ","))
	}
	if c.Credentials {
		cx.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	if c.MaxAge > 0 {
		cx.Writer.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", int(c.MaxAge.Seconds())))
	}
}

//
// refreshIdentity refreshes the access token for the user
//
func (r keycloakProxy) refreshIdentity(cx *gin.Context, user *userContext, refresh *RefreshToken) (jose.JWT, error) {
	// step: attempts to refresh the access token
	token, expires, err := r.refreshToken(refresh.Token())
	if err != nil {
		// step: has the refresh token expired
		switch err {
		case ErrRefreshTokenExpired:
			log.WithFields(log.Fields{"token": token}).Warningf("the refresh token has expired")
			clearAllCookies(cx)
		default:
			log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to refresh the access token")
		}

		return token, err
	}

	// step: inject the refreshed access token
	log.WithFields(log.Fields{
		"access_expires_in":  expires.Sub(time.Now()).String(),
		"refresh_expires_in": refresh.Expiration().Sub(time.Now()).String(),
	}).Infof("injecting refreshed access token, expires on: %s", expires.Format(time.RFC1123))

	// step: clear the cookie up
	dropAccessTokenCookie(cx, token)

	return token, nil
}

//
// StoreRefreshToken the token to the store
//
func (r keycloakProxy) StoreRefreshToken(token *jose.JWT, value string) error {
	return r.store.Set(getHashKey(token), value)
}

//
// Get retrieves a token from the store, the key we are using here is the access token
//
func (r keycloakProxy) GetRefreshToken(token *jose.JWT) (string, error) {
	// step: the key is the access token
	v, err := r.store.Get(getHashKey(token))
	if err != nil {
		return v, err
	}
	if v == "" {
		return v, ErrNoSessionStateFound
	}

	return v, nil
}

//
// DeleteRefreshToken removes a key from the store
//
func (r keycloakProxy) DeleteRefreshToken(token jose.JWT) error {
	if err := r.store.Delete(getHashKey(&token)); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Errorf("failed to delete the token from store")

		return err
	}

	return nil
}

// Close is used to close off any resources
func (r keycloakProxy) CloseStore() error {
	if r.store != nil {
		return r.store.Close()
	}

	return nil
}

func getHashKey(token *jose.JWT) string {
	return string(sha256.New().Sum([]byte(token.Encode())))
}
