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
)

// IsValid ensure the resource is valid
func (r *Resource) IsValid() error {
	// step: ensure everything is initialized
	if r.Methods == nil {
		r.Methods = make([]string, 0)
	}
	if r.Roles == nil {
		r.Roles = make([]string, 0)
	}

	if strings.HasPrefix(r.URL, oauthURL) {
		return fmt.Errorf("this is used by the oauth handlers")
	}

	// step: check we have a url
	if r.URL == "" {
		return fmt.Errorf("resource does not have url")
	}

	// step: add any of no methods
	if len(r.Methods) <= 0 {
		r.Methods = append(r.Methods, "ANY")
	}

	// step: check the method is valid
	for _, m := range r.Methods {
		if !isValidMethod(m) {
			return fmt.Errorf("invalid method %s", m)
		}
	}

	return nil
}

// GetRoles gets a list of roles
func (r Resource) GetRoles() string {
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
