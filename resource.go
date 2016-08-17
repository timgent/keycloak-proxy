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
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func newResource() *Resource {
	return &Resource{}
}

//
// parse decodes a resource definition
//
func (r *Resource) parse(resource string) (*Resource, error) {
	if resource == "" {
		return nil, errors.New("the resource has no options")
	}

	for _, x := range strings.Split(resource, "|") {
		kp := strings.Split(x, "=")
		if len(kp) != 2 {
			return nil, errors.New("invalid resource keypair, should be (uri|roles|methods|white-listed)=comma_values")
		}
		switch kp[0] {
		case "uri":
			r.URL = kp[1]
		case "methods":
			r.Methods = strings.Split(kp[1], ",")
		case "roles":
			r.Roles = strings.Split(kp[1], ",")
		case "white-listed":
			value, err := strconv.ParseBool(kp[1])
			if err != nil {
				return nil, errors.New("the value of whitelisted must be true|TRUE|T or it's false equivilant")
			}
			r.WhiteListed = value
		default:
			return nil, errors.New("invalid identifier, should be roles, uri or methods")
		}
	}

	return r, nil
}

//
// valid ensure the resource is valid
//
func (r *Resource) valid() error {
	if r.Methods == nil {
		r.Methods = make([]string, 0)
	}
	if r.Roles == nil {
		r.Roles = make([]string, 0)
	}

	if strings.HasPrefix(r.URL, oauthURL) {
		return errors.New("this is used by the oauth handlers")
	}

	// step: check we have a url
	if r.URL == "" {
		return errors.New("resource does not have url")
	}

	// step: add any of no methods
	if len(r.Methods) <= 0 {
		r.Methods = append(r.Methods, "ANY")
	}

	// step: check the method is valid
	for _, m := range r.Methods {
		if !isValidHTTPMethod(m) {
			return fmt.Errorf("invalid method %s", m)
		}
	}

	return nil
}

// getRoles gets a list of roles
func (r Resource) getRoles() string {
	return strings.Join(r.Roles, ",")
}

// String returns a string representation of the resource
func (r Resource) String() string {
	if r.WhiteListed {
		return fmt.Sprintf("uri: %s, white-listed", r.URL)
	}

	roles := "authentication only"
	methods := "ANY"

	if len(r.Roles) > 0 {
		roles = strings.Join(r.Roles, ",")
	}

	if len(r.Methods) > 0 {
		methods = strings.Join(r.Methods, ",")
	}

	return fmt.Sprintf("uri: %s, methods: %s, required: %s", r.URL, methods, roles)
}
