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
	"strings"
	"time"
)

func newRefreshToken(encoded string) (*RefreshToken, error) {
	// step: extracts the sections from the state
	sections := strings.Split(string(encoded), "|")
	if len(sections) != 2 {
		return nil, ErrInvalidSession
	}
	// step: convert the unix timestamp
	expiration, err := convertUnixTime(sections[0])
	if err != nil {
		return nil, ErrInvalidSession
	}

	return &RefreshToken{
		expireOn: expiration,
		token:    sections[1],
	}, nil
}

func (r RefreshToken) Expiration() time.Time {
	return r.expireOn
}

func (r *RefreshToken) SetExpiration(expires time.Time) *RefreshToken {
	r.expireOn = expires

	return r
}

func (r *RefreshToken) SetToken(token string) *RefreshToken {
	r.token = token

	return r
}

func (r RefreshToken) String() string {
	return r.Encode()
}

func (r RefreshToken) Encode() string {
	return fmt.Sprintf("%d|%s", r.expireOn.Unix(), r.token)
}

func (r RefreshToken) Token() string {
	return r.token
}

func (r RefreshToken) IsExpired() bool {
	return r.expireOn.Before(time.Now())
}
