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
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewRefreshToken(t *testing.T) {
	timestamp := time.Now()

	cases := []struct {
		Encoded string
		Token   RefreshToken
		Ok      bool
	}{
		{
			Encoded: fmt.Sprintf("%d|test_token", timestamp.Unix()),
			Token: RefreshToken{
				expireOn: timestamp,
				token:    "test_token",
			},
			Ok: true,
		},
		{
			Encoded: "|test_token",
		},
	}

	for i, c := range cases {
		token, err := newRefreshToken(c.Encoded)
		if !c.Ok && err == nil {
			t.Errorf("case %d should thrown an error: %s", i, err)
			continue
		}
		if err != nil {
			continue
		}
		if reflect.DeepEqual(token, c.Token) {
			t.Errorf("case %d the token are not the same, expectd: %v got: %v", i, c.Token, token)
		}
	}
}

func TestRefreshTokenString(t *testing.T) {
	token, err := newRefreshToken("1460721776|test_token")
	assert.NoError(t, err)
	assert.Equal(t, "1460721776|test_token", token.String())
}

func TestRefreshTokenEncode(t *testing.T) {
	token := RefreshToken{
		expireOn: time.Now(),
		token:    "test_token",
	}
	assert.Equal(t, fmt.Sprintf("%d|test_token", token.expireOn.Unix()), token.Encode())
}

func TestRefreshTokenToken(t *testing.T) {
	assert.Equal(t, "test_token", RefreshToken{
		expireOn: time.Now(),
		token:    "test_token",
	}.Token())
}

func TestRefreshTokenIsExpired(t *testing.T) {
	assert.False(t, RefreshToken{
		expireOn: time.Now().Add(1 * time.Hour),
	}.IsExpired())

	assert.True(t, RefreshToken{
		expireOn: time.Now().Add(-10 * time.Hour),
	}.IsExpired())
}
