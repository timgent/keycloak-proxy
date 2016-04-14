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
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/gin-gonic/gin"
)

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
func (r *keycloakProxy) setupTemplates() error {
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

	return nil
}
