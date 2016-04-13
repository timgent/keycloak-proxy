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
	"strings"

	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oauth2"
)

//
// refreshToken attempts to refresh the access token, returning the parsed token and the time it expires or a error
//
func (r *keycloakProxy) refreshToken(refreshToken string) (jose.JWT, error) {
	response, err := r.getToken(oauth2.GrantTypeRefreshToken, refreshToken)
	if err != nil {
		if strings.Contains(err.Error(), "token expired") {
			return jose.JWT{}, ErrRefreshTokenExpired
		}
		return jose.JWT{}, err
	}
	// step: parse the access token
	token, _, err := parseToken(response.AccessToken)
	if err != nil {
		return jose.JWT{}, err
	}

	return token, nil
}

//
// verifyToken verify that the token in the user context is valid
//
func (r *keycloakProxy) verifyToken(token jose.JWT) error {
	// step: verify the token is whom they say they are
	if err := r.client.VerifyJWT(token); err != nil {
		if strings.Contains(err.Error(), "token is expired") {
			return ErrAccessTokenExpired
		}

		return err
	}

	return nil
}

//
// getToken retrieves a code from the provider, extracts and verified the token
//
func (r *keycloakProxy) getToken(grantType, code string) (oauth2.TokenResponse, error) {
	// step: retrieve the client
	client, err := r.client.OAuthClient()
	if err != nil {
		return oauth2.TokenResponse{}, err
	}

	// step: request a token from the authentication server
	return  client.RequestToken(grantType, code)
}

