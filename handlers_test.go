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
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/jose"
	"github.com/gin-gonic/gin"
)

func TestEntrypointHandlerSecure(t *testing.T) {
	proxy := newFakeKeycloakProxyWithResources(t, []*Resource{
		{
			URL:         "/admin/white_listed",
			WhiteListed: true,
		},
		{
			URL:     "/admin",
			Methods: []string{"ANY"},
		},
		{
			URL:     "/",
			Methods: []string{"POST"},
			Roles:   []string{"test"},
		},
	})

	handler := proxy.entryPointHandler()

	tests := []struct {
		Context *gin.Context
		Secure  bool
	}{
		{Context: newFakeGinContext("GET", "/")},
		{Context: newFakeGinContext("GET", "/admin"), Secure: true},
		{Context: newFakeGinContext("GET", "/admin/white_listed")},
		{Context: newFakeGinContext("GET", "/admin/white"), Secure: true},
		{Context: newFakeGinContext("GET", "/not_secure")},
		{Context: newFakeGinContext("POST", "/"), Secure: true},
	}

	for i, c := range tests {
		handler(c.Context)
		_, found := c.Context.Get(cxEnforce)
		if c.Secure && !found {
			t.Errorf("test case %d should have been set secure", i)
		}
		if !c.Secure && found {
			t.Errorf("test case %d should not have been set secure", i)
		}
	}
}

func TestEntrypointMethods(t *testing.T) {
	proxy := newFakeKeycloakProxyWithResources(t, []*Resource{
		{
			URL:     "/u0",
			Methods: []string{"GET", "POST"},
		},
		{
			URL:     "/u1",
			Methods: []string{"ANY"},
		},
		{
			URL:     "/u2",
			Methods: []string{"POST", "PUT"},
		},
	})

	handler := proxy.entryPointHandler()

	tests := []struct {
		Context *gin.Context
		Secure  bool
	}{
		{Context: newFakeGinContext("GET", "/u0"), Secure: true},
		{Context: newFakeGinContext("POST", "/u0"), Secure: true},
		{Context: newFakeGinContext("PUT", "/u0"), Secure: false},
		{Context: newFakeGinContext("GET", "/u1"), Secure: true},
		{Context: newFakeGinContext("POST", "/u1"), Secure: true},
		{Context: newFakeGinContext("PATCH", "/u1"), Secure: true},
		{Context: newFakeGinContext("POST", "/u2"), Secure: true},
		{Context: newFakeGinContext("PUT", "/u2"), Secure: true},
		{Context: newFakeGinContext("DELETE", "/u2"), Secure: false},
	}

	for i, c := range tests {
		handler(c.Context)
		_, found := c.Context.Get(cxEnforce)
		if c.Secure && !found {
			t.Errorf("test case %d should have been set secure", i)
		}
		if !c.Secure && found {
			t.Errorf("test case %d should not have been set secure", i)
		}
	}
}

func TestEntrypointWhiteListing(t *testing.T) {
	proxy := newFakeKeycloakProxyWithResources(t, []*Resource{
		{
			URL:         "/admin/white_listed",
			WhiteListed: true,
		},
		{
			URL:     "/admin",
			Methods: []string{"ANY"},
		},
	})
	handler := proxy.entryPointHandler()

	tests := []struct {
		Context *gin.Context
		Secure  bool
	}{
		{Context: newFakeGinContext("GET", "/")},
		{Context: newFakeGinContext("GET", "/admin"), Secure: true},
		{Context: newFakeGinContext("GET", "/admin/white_listed")},
	}

	for i, c := range tests {
		handler(c.Context)
		_, found := c.Context.Get(cxEnforce)
		if c.Secure && !found {
			t.Errorf("test case %d should have been set secure", i)
		}
		if !c.Secure && found {
			t.Errorf("test case %d should not have been set secure", i)
		}
	}

}

func TestEntrypointHandler(t *testing.T) {
	proxy := newFakeKeycloakProxy(t)
	handler := proxy.entryPointHandler()

	tests := []struct {
		Context *gin.Context
		Secure  bool
	}{
		{Context: newFakeGinContext("GET", fakeAdminRoleURL), Secure: true},
		{Context: newFakeGinContext("GET", fakeAdminRoleURL+"/sso"), Secure: true},
		{Context: newFakeGinContext("GET", fakeAdminRoleURL+"/../sso"), Secure: true},
		{Context: newFakeGinContext("GET", "/not_secure")},
		{Context: newFakeGinContext("GET", fakeTestWhitelistedURL)},
		{Context: newFakeGinContext("GET", oauthURL)},
		{Context: newFakeGinContext("GET", fakeTestListenOrdered), Secure: true},
	}

	for i, c := range tests {
		handler(c.Context)
		_, found := c.Context.Get(cxEnforce)
		if c.Secure && !found {
			t.Errorf("test case %d should have been set secure", i)
		}
		if !c.Secure && found {
			t.Errorf("test case %d should not have been set secure", i)
		}
	}
}

func TestAdmissionHandlerRoles(t *testing.T) {
	proxy := newFakeKeycloakProxyWithResources(t, []*Resource{
		{
			URL:     "/admin",
			Methods: []string{"ANY"},
			Roles:   []string{"admin"},
		},
		{
			URL:     "/test",
			Methods: []string{"GET"},
			Roles:   []string{"test"},
		},
		{
			URL:     "/either",
			Methods: []string{"ANY"},
			Roles:   []string{"admin", "test"},
		},
		{
			URL:     "/",
			Methods: []string{"ANY"},
		},
	})
	handler := proxy.admissionHandler()

	tests := []struct {
		Context     *gin.Context
		UserContext *userContext
		HTTPCode    int
	}{
		{
			Context:     newFakeGinContext("GET", "/admin"),
			UserContext: &userContext{},
			HTTPCode:    http.StatusForbidden,
		},
		{
			Context:  newFakeGinContext("GET", "/admin"),
			HTTPCode: http.StatusOK,
			UserContext: &userContext{
				roles: []string{"admin"},
			},
		},
		{
			Context:  newFakeGinContext("GET", "/test"),
			HTTPCode: http.StatusOK,
			UserContext: &userContext{
				roles: []string{"test"},
			},
		},
		{
			Context:  newFakeGinContext("GET", "/either"),
			HTTPCode: http.StatusOK,
			UserContext: &userContext{
				roles: []string{"test", "admin"},
			},
		},
		{
			Context:  newFakeGinContext("GET", "/either"),
			HTTPCode: http.StatusForbidden,
			UserContext: &userContext{
				roles: []string{"no_roles"},
			},
		},
		{
			Context:     newFakeGinContext("GET", "/"),
			HTTPCode:    http.StatusOK,
			UserContext: &userContext{},
		},
	}

	for i, c := range tests {
		// step: find the resource and inject into the context
		for _, r := range proxy.config.Resources {
			if strings.HasPrefix(c.Context.Request.URL.Path, r.URL) {
				c.Context.Set(cxEnforce, r)
				break
			}
		}
		if _, found := c.Context.Get(cxEnforce); !found {
			t.Errorf("test case %d unable to find a resource for context", i)
			continue
		}

		c.Context.Set(userContextName, c.UserContext)

		handler(c.Context)
		if c.Context.Writer.Status() != c.HTTPCode {
			t.Errorf("test case %d should have recieved code: %d, got %d", i, c.HTTPCode, c.Context.Writer.Status())
		}
	}
}

func TestAdmissionHandlerClaims(t *testing.T) {
	// allow any fake authed users
	proxy := newFakeKeycloakProxyWithResources(t, []*Resource{
		{
			URL:     "/admin",
			Methods: []string{"ANY"},
		},
	})

	tests := []struct {
		Matches     map[string]string
		Context     *gin.Context
		UserContext *userContext
		HTTPCode    int
	}{
		{
			Matches: map[string]string{"iss": "test"},
			Context: newFakeGinContext("GET", "/admin"),
			UserContext: &userContext{
				claims: jose.Claims{},
			},
			HTTPCode: http.StatusForbidden,
		},
		{
			Matches: map[string]string{"iss": "^tes$"},
			Context: newFakeGinContext("GET", "/admin"),
			UserContext: &userContext{
				claims: jose.Claims{"iss": 1},
			},
			HTTPCode: http.StatusForbidden,
		},
		{
			Matches: map[string]string{"iss": "^tes$"},
			Context: newFakeGinContext("GET", "/admin"),
			UserContext: &userContext{
				claims: jose.Claims{"iss": "bad_match"},
			},
			HTTPCode: http.StatusForbidden,
		},
		{
			Matches: map[string]string{"iss": "^test", "notfound": "someting"},
			Context: newFakeGinContext("GET", "/admin"),
			UserContext: &userContext{
				claims: jose.Claims{"iss": "test"},
			},
			HTTPCode: http.StatusForbidden,
		},
		{
			Matches: map[string]string{"iss": "^test", "notfound": "someting"},
			Context: newFakeGinContext("GET", "/admin"),
			UserContext: &userContext{
				claims: jose.Claims{"iss": "test"},
			},
			HTTPCode: http.StatusForbidden,
		},
		{
			Matches: map[string]string{"iss": ".*"},
			Context: newFakeGinContext("GET", "/admin"),
			UserContext: &userContext{
				claims: jose.Claims{"iss": "test"},
			},
			HTTPCode: http.StatusOK,
		},
		{
			Matches: map[string]string{"iss": "^t.*$"},
			Context: newFakeGinContext("GET", "/admin"),
			UserContext: &userContext{
				claims: jose.Claims{"iss": "test"},
			},
			HTTPCode: http.StatusOK,
		},
	}

	for i, c := range tests {
		// step: if closure so we need to get the handler each time
		proxy.config.ClaimsMatch = c.Matches
		handler := proxy.admissionHandler()
		// step: inject a resource

		c.Context.Set(cxEnforce, proxy.config.Resources[0])
		c.Context.Set(userContextName, c.UserContext)

		handler(c.Context)
		if c.Context.Writer.Status() != c.HTTPCode {
			t.Errorf("test case %d should have recieved code: %d, got %d", i, c.HTTPCode, c.Context.Writer.Status())
		}
	}
}

func TestSecurityHandler(t *testing.T) {
	kc := newFakeKeycloakProxy(t)
	handler := kc.securityHandler()
	context := newFakeGinContext("GET", "/")
	handler(context)
	if context.Writer.Status() != http.StatusOK {
		t.Errorf("we should have received a 200")
	}

	kc = newFakeKeycloakProxy(t)
	kc.config.Hostnames = []string{"127.0.0.1"}
	handler = kc.securityHandler()
	handler(context)
	if context.Writer.Status() != http.StatusOK {
		t.Errorf("we should have received a 200 not %d", context.Writer.Status())
	}

	kc = newFakeKeycloakProxy(t)
	kc.config.Hostnames = []string{"127.0.0.2"}
	handler = kc.securityHandler()
	handler(context)
	if context.Writer.Status() != http.StatusInternalServerError {
		t.Errorf("we should have received a 500 not %d", context.Writer.Status())
	}
}

func newFakeJWTToken(t *testing.T, claims jose.Claims) *jose.JWT {
	token, err := jose.NewJWT(
		jose.JOSEHeader{"alg": "RS256"}, claims,
	)
	if err != nil {
		t.Fatalf("failed to create the jwt token, error: %s", err)
	}

	return &token
}

func TestExpirationHandler(t *testing.T) {
	proxy := newFakeKeycloakProxy(t)

	cases := []struct {
		Token    *jose.JWT
		HTTPCode int
	}{
		{
			HTTPCode: http.StatusUnauthorized,
		},
		{
			Token: newFakeJWTToken(t, jose.Claims{
				"exp": float64(time.Now().Add(-24 * time.Hour).Unix()),
			}),
			HTTPCode: http.StatusInternalServerError,
		},
		{
			Token: newFakeJWTToken(t, jose.Claims{
				"exp":                float64(time.Now().Add(10 * time.Hour).Unix()),
				"iss":                "https://keycloak.example.com/auth/realms/commons",
				"sub":                "1e11e539-8256-4b3b-bda8-cc0d56cddb48",
				"email":              "gambol99@gmail.com",
				"name":               "Rohith Jayawardene",
				"preferred_username": "rjayawardene",
			}),
			HTTPCode: http.StatusOK,
		},
		{
			Token: newFakeJWTToken(t, jose.Claims{
				"exp":                float64(time.Now().Add(-24 * time.Hour).Unix()),
				"iss":                "https://keycloak.example.com/auth/realms/commons",
				"sub":                "1e11e539-8256-4b3b-bda8-cc0d56cddb48",
				"email":              "gambol99@gmail.com",
				"name":               "Rohith Jayawardene",
				"preferred_username": "rjayawardene",
			}),
			HTTPCode: http.StatusForbidden,
		},
	}

	for i, c := range cases {
		// step: inject a resource
		cx := newFakeGinContext("GET", "/oauth/expiration")
		// step: add the token is there is one
		if c.Token != nil {
			cx.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.Token.Encode()))
		}
		// step: if closure so we need to get the handler each time
		proxy.expirationHandler(cx)
		// step: check the content result
		if cx.Writer.Status() != c.HTTPCode {
			t.Errorf("test case %d should have recieved: %d, but got %d", i, c.HTTPCode, cx.Writer.Status())
		}
	}
}

func TestHealthHandler(t *testing.T) {
	proxy := newFakeKeycloakProxy(t)
	context := newFakeGinContext("GET", healthURL)
	proxy.healthHandler(context)
	if context.Writer.Status() != http.StatusOK {
		t.Errorf("we should have recieved a 200 response")
	}
}
