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
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/armon/go-proxyproto"
	"github.com/coreos/go-oidc/oidc"
	"github.com/elazarl/goproxy"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	httplog "log"
)

type oauthProxy struct {
	// the proxy configuration
	config *Config
	// the gin service
	router http.Handler
	// the opened client
	client *oidc.Client
	// the openid provider configuration
	provider oidc.ProviderConfig
	// the proxy client
	upstream reverseProxy
	// the upstream endpoint url
	endpoint *url.URL
	// the store interface
	store storage
	// the prometheus handler
	prometheusHandler http.Handler
}

func init() {
	// step: ensure all time is in UTC
	time.LoadLocation("UTC")
	// step: set the core
	runtime.GOMAXPROCS(runtime.NumCPU())
}

//
// newProxy create's a new proxy from configuration
//
func newProxy(config *Config) (*oauthProxy, error) {
	var err error
	// step: set the logger
	httplog.SetOutput(ioutil.Discard)

	// step: set the logging level
	if config.LogJSONFormat {
		log.SetFormatter(&log.JSONFormatter{})
	}
	// step: set the logging level
	gin.SetMode(gin.ReleaseMode)
	if config.Verbose {
		log.SetLevel(log.DebugLevel)
		gin.SetMode(gin.DebugMode)
		httplog.SetOutput(os.Stderr)
	}

	log.Infof("starting %s, author: %s, version: %s, ", prog, author, version)

	service := &oauthProxy{
		config:            config,
		prometheusHandler: prometheus.Handler(),
	}

	// step: parse the upstream endpoint
	if service.endpoint, err = url.Parse(config.Upstream); err != nil {
		return nil, err
	}

	// step: initialize the store if any
	if config.StoreURL != "" {
		if service.store, err = createStorage(config.StoreURL); err != nil {
			return nil, err
		}
	}

	// step: initialize the openid client
	if !config.SkipTokenVerification {
		if service.client, service.provider, err = createOpenIDClient(config); err != nil {
			return nil, err
		}
	} else {
		log.Warnf("TESTING ONLY CONFIG - the verification of the token have been disabled")
	}

	if config.ClientID == "" && config.ClientSecret == "" {
		log.Warnf("Note: client credentials are not set, depending on provider (confidential|public) you might be unable to auth")
	}

	// step: are we running in forwarding more?
	switch config.EnableForwarding {
	case true:
		if err := service.createForwardingProxy(); err != nil {
			return nil, err
		}
	default:
		if err := service.createReverseProxy(); err != nil {
			return nil, err
		}
	}

	return service, nil
}

//
// createReverseProxy creates a reverse proxy
//
func (r *oauthProxy) createReverseProxy() error {
	log.Infof("enabled reverse proxy mode, upstream url: %s", r.config.Upstream)

	// step: display the protected resources
	for _, resource := range r.config.Resources {
		log.Infof("protecting resources under uri: %s", resource)
	}
	for name, value := range r.config.MatchClaims {
		log.Infof("the token must container the claim: %s, required: %s", name, value)
	}

	// step: initialize the reverse http proxy
	if err := r.createUpstreamProxy(r.endpoint); err != nil {
		return err
	}

	//step: create the gin router
	engine := gin.New()
	engine.Use(gin.Recovery())

	// step: are we logging the traffic?
	if r.config.LogRequests {
		engine.Use(r.loggingMiddleware())
	}

	// step: enabling the metrics?
	if r.config.EnableMetrics {
		engine.Use(r.metricsMiddleware())
	}

	// step: enabling the security filter?
	if r.config.EnableSecurityFilter {
		engine.Use(r.securityMiddleware())
	}

	// step: add the routing
	oauth := engine.Group(oauthURL).Use(r.corsMiddleware(r.config.CrossOrigin))
	oauth.GET(authorizationURL, r.oauthAuthorizationHandler)
	oauth.GET(callbackURL, r.oauthCallbackHandler)
	oauth.GET(healthURL, r.healthHandler)
	oauth.GET(tokenURL, r.tokenHandler)
	oauth.GET(expiredURL, r.expirationHandler)
	oauth.GET(logoutURL, r.logoutHandler)
	oauth.POST(loginURL, r.loginHandler)
	// step: enable the metric page?
	if r.config.EnableMetrics {
		oauth.GET(metricsURL, r.metricsHandler)
	}

	// step: add the middleware
	engine.Use(r.entrypointMiddleware(), r.authenticationMiddleware(), r.admissionMiddleware(),
		r.headersMiddleware(r.config.AddClaims), r.reverseProxyMiddleware())

	// step: set the handler
	r.router = engine

	// step: load the templates
	if err := r.createTemplates(); err != nil {
		return err
	}

	return nil
}

//
// createForwardingProxy creates a forwarding proxy
//
func (r *oauthProxy) createForwardingProxy() error {
	log.Infof("enabling forward signing mode, listening on %s", r.config.Listen)

	if r.config.SkipUpstreamTLSVerify {
		log.Warnf("TLS verification switched off. In forward signing mode it's recommended you verify! (--skip-upstream-tls-verify=false)")
	}

	// step: initialize the reverse http proxy
	if err := r.createUpstreamProxy(nil); err != nil {
		return err
	}

	// step: setup and initialize the handler
	forwardingHandler := r.forwardProxyHandler()

	// step: set the http handler
	proxy := r.upstream.(*goproxy.ProxyHttpServer)
	r.router = proxy

	// step: setup the tls configuration
	if r.config.TLSCaCertificate != "" && r.config.TLSCaPrivateKey != "" {
		// step: read in the ca
		ca, err := loadCA(r.config.TLSCaCertificate, r.config.TLSCaPrivateKey)
		if err != nil {
			return fmt.Errorf("unable to load certificate authority, error: %s", err)
		}
		// step: implement the goproxy connect method
		proxy.OnRequest().HandleConnectFunc(
			func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
				return &goproxy.ConnectAction{
					Action:    goproxy.ConnectMitm,
					TLSConfig: goproxy.TLSConfigFromCA(ca),
				}, host
			},
		)
	} else {
		// step: use the default certificate provided by goproxy
		proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	}

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		// @NOTES, somewhat annoying but goproxy hands back a nil response on proxy client
		// errors
		if resp != nil && r.config.LogRequests {
			start := ctx.UserData.(time.Time)
			latency := time.Now().Sub(start)

			log.WithFields(log.Fields{
				"method":  resp.Request.Method,
				"status":  resp.StatusCode,
				"bytes":   resp.ContentLength,
				"host":    resp.Request.Host,
				"path":    resp.Request.URL.Path,
				"latency": latency.String(),
			}).Infof("[%d] |%s| |%10v| %-5s %s", resp.StatusCode, resp.Request.Host, latency, resp.Request.Method, resp.Request.URL.Path)
		}

		return resp
	})
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ctx.UserData = time.Now()
		// step: forward into the handler
		forwardingHandler(req, ctx.Resp)

		return req, ctx.Resp
	})

	return nil
}

//
// Run starts the proxy service
//
func (r *oauthProxy) Run() (err error) {
	tlsConfig := &tls.Config{}

	// step: are we doing mutual tls?
	if r.config.TLSCaCertificate != "" {
		log.Infof("enabling mutual tls, reading in the signing ca: %s", r.config.TLSCaCertificate)
		caCert, err := ioutil.ReadFile(r.config.TLSCaCertificate)
		if err != nil {
			return err
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	server := &http.Server{
		Addr:    r.config.Listen,
		Handler: r.router,
	}

	// step: create the listener
	var listener net.Listener
	switch strings.HasPrefix(r.config.Listen, "unix://") {
	case true:
		socket := strings.Trim(r.config.Listen, "unix://")
		// step: delete the socket if it exists
		if exists := fileExists(socket); exists {
			if err := os.Remove(socket); err != nil {
				return err
			}
		}

		log.Infof("listening on unix socket: %s", r.config.Listen)
		if listener, err = net.Listen("unix", socket); err != nil {
			return err
		}

	default:
		listener, err = net.Listen("tcp", r.config.Listen)
		if err != nil {
			return err
		}
	}

	// step: configure tls
	if r.config.TLSCertificate != "" && r.config.TLSPrivateKey != "" {
		server.TLSConfig = tlsConfig
		if tlsConfig.NextProtos == nil {
			tlsConfig.NextProtos = []string{"http/1.1"}
		}
		if len(tlsConfig.Certificates) == 0 || r.config.TLSCertificate != "" || r.config.TLSPrivateKey != "" {
			tlsConfig.Certificates = make([]tls.Certificate, 1)
			if tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(r.config.TLSCertificate, r.config.TLSPrivateKey); err != nil {
				return err
			}
		}
		log.Infof("tls enabled, certificate: %s, key: %s", r.config.TLSCertificate, r.config.TLSPrivateKey)

		listener = tls.NewListener(listener, tlsConfig)
	}

	// step: wrap the listen in a proxy protocol
	if r.config.EnableProxyProtocol {
		log.Infof("enabling the proxy protocol on listener: %s", r.config.Listen)
		listener = &proxyproto.Listener{listener}
	}

	go func() {
		log.Infof("keycloak proxy service starting on %s", r.config.Listen)
		if err = server.Serve(listener); err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
			}).Fatalf("failed to start the service")
		}
	}()

	return nil
}

//
// createUpstreamProxy create a reverse http proxy from the upstream
//
func (r *oauthProxy) createUpstreamProxy(upstream *url.URL) error {
	// step: create the default dialer
	dialer := (&net.Dialer{
		KeepAlive: r.config.UpstreamKeepaliveTimeout,
		Timeout:   r.config.UpstreamTimeout,
	}).Dial

	// step: are we using a unix socket?
	if upstream != nil && upstream.Scheme == "unix" {
		log.Infof("using the unix domain socket: %s%s for upstream", upstream.Host, upstream.Path)
		socketPath := fmt.Sprintf("%s%s", upstream.Host, upstream.Path)
		dialer = func(network, address string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		}
		upstream.Path = ""
		upstream.Host = "domain-sock"
		upstream.Scheme = "http"
	}

	// step: create the upstream tls configure
	tlsConfig := &tls.Config{
		InsecureSkipVerify: r.config.SkipUpstreamTLSVerify,
	}

	// step: are we using a client certificate
	// @TODO provide a means of reload on the client certificate when it expires. I'm not sure if it's just a
	// case of update the http transport settings - Also we to place this go-routine?
	if r.config.TLSClientCertificate != "" {
		cert, err := ioutil.ReadFile(r.config.TLSClientCertificate)
		if err != nil {
			log.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(cert)

		// step: update the upstream tls to use the client certificate
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	// step: create the forwarding proxy
	proxy := goproxy.NewProxyHttpServer()
	proxy.Logger = httplog.New(ioutil.Discard, "", 0)
	r.upstream = proxy

	// step: update the tls configuration of the reverse proxy
	r.upstream.(*goproxy.ProxyHttpServer).Tr = &http.Transport{
		Dial:              dialer,
		TLSClientConfig:   tlsConfig,
		DisableKeepAlives: !r.config.UpstreamKeepalives,
	}

	return nil
}

//
// createTemplates loads the custom template
//
func (r *oauthProxy) createTemplates() error {
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
		r.router.(*gin.Engine).LoadHTMLFiles(list...)
	}

	return nil
}
