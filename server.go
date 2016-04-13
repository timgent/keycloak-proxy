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
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/oidc"

	log "github.com/Sirupsen/logrus"
	"github.com/gin-gonic/gin"
)

//
// keycloakProxy is the server component
//
type keycloakProxy struct {
	Store
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
	service.upstream, err = service.setupReverseProxy(cfg.Upstream)
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
	router := gin.New()
	service.router = router

	// step: load the templates
	if err = service.setupTemplates(); err != nil {
		return nil, err
	}

	if err := service.setupRouter(); err != nil {
		return nil, err
	}

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
// setupRouter sets up the gin routing
//
func (r keycloakProxy) setupRouter() error {
	r.router.Use(gin.Recovery())
	// step: are we logging the traffic?
	if r.config.LogRequests {
		r.router.Use(r.loggingHandler())
	}
	// step: enabling the security filter?
	if r.config.EnableSecurityFilter {
		r.router.Use(r.securityHandler())
	}
	// step: add the routing
	r.router.GET(authorizationURL, r.oauthAuthorizationHandler)
	r.router.GET(callbackURL, r.oauthCallbackHandler)
	r.router.GET(healthURL, r.healthHandler)
	r.router.GET(tokenURL, r.tokenHandler)
	r.router.GET(expiredURL, r.expirationHandler)
	r.router.Use(r.entryPointHandler(), r.authenticationHandler(), r.admissionHandler())

	return nil
}

//
// setupTemplates loads the custom template
//
func (r *keycloakProxy) setupTemplates() {
	var list []string

	if r.config.SignInPage != "" {
		log.Debugf("loading the custom sign in page: %s", r.config.SignInPage)
		list = append(list, r.config.SignInPage)
	}
	if r.config.ForbiddenPage != "" {
		log.Debugf("loading the custom sign forbidden page: %s", r.config.ForbiddenPage)
		list = append(list, r.config.ForbiddenPage)
	}

	if len(list) > 0 {
		log.Infof("loading the custom templates: %s", strings.Join(list, ","))
		r.router.LoadHTMLFiles(list...)
	}
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
// tryUpdateConnection attempt to upgrade the connection to a http pdy stream
//
func (r *keycloakProxy) tryUpdateConnection(cx *gin.Context) error {
	// step: dial the endpoint
	tlsConn, err := tryDialEndpoint(r.endpoint)
	if err != nil {
		return err
	}
	defer tlsConn.Close()

	// step: we need to hijack the underlining client connection
	clientConn, _, err := cx.Writer.(http.Hijacker).Hijack()
	if err != nil {
		return err
	}
	defer clientConn.Close()

	// step: write the request to upstream
	if err = cx.Request.Write(tlsConn); err != nil {
		return err
	}

	// step: copy the date between client and upstream endpoint
	var wg sync.WaitGroup
	wg.Add(2)
	go transferBytes(tlsConn, clientConn, &wg)
	go transferBytes(clientConn, tlsConn, &wg)
	wg.Wait()

	return nil
}

//
// setupReverseProxy create a reverse http proxy from the upstream
//
func (r *keycloakProxy) setupReverseProxy(upstream *url.URL) (reverseProxy, error) {
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	// step: we don't care about the cert verification here
	proxy.Transport = &http.Transport{
		Dial: (&net.Dialer{
			KeepAlive: 10 * time.Second,
			Timeout:   10 * time.Second,
		}).Dial,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: r.config.SkipUpstreamTLSVerify,
		},
		DisableKeepAlives:   !r.config.Keepalives,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return proxy, nil
}

// Add the token to the store
func (r keycloakProxy) Set(key string, value string) error {
	// step: encrpyt the value




	return nil
}

// Get retrieves a token from the store
func (r keycloakProxy) Get(key string) (string, error) {
	// step: the key is the access token


	return "", nil
}

// Delete removes a key from the store
func (r keycloakProxy) Delete(string) error {
	return nil
}

// Close is used to close off any resources
func (r keycloakProxy) Close() error {
	return nil
}
