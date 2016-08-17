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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeResource(t *testing.T) {
	testCases := []struct {
		Option   string
		Ok       bool
		Resource *Resource
	}{
		{
			Option: "uri=/admin",
			Ok:     true,
			Resource: &Resource{
				URL: "/admin",
			},
		},
		{
			Option: "uri=/",
			Ok:     true,
			Resource: &Resource{
				URL: "/",
			},
		},
		{
			Option: "uri=/admin/sso|roles=test,test1",
			Ok:     true,
			Resource: &Resource{
				URL:   "/admin/sso",
				Roles: []string{"test", "test1"},
			},
		},
		{
			Option: "uri=/admin/sso|roles=test,test1|methods=GET,POST",
			Ok:     true,
			Resource: &Resource{
				URL:     "/admin/sso",
				Roles:   []string{"test", "test1"},
				Methods: []string{"GET", "POST"},
			},
		},
		{
			Option: "uri=/allow_me|white-listed=true",
			Ok:     true,
			Resource: &Resource{
				URL:         "/allow_me",
				WhiteListed: true,
			},
		},
		{
			Option: "",
		},
	}

	for i, c := range testCases {
		rc, err := newResource().parse(c.Option)
		if c.Ok && err != nil {
			t.Errorf("test case %d should not have failed, error: %s", i, err)
			continue
		}
		assert.Equal(t, rc, c.Resource)
	}
}

func TestIsValid(t *testing.T) {
	testCases := []struct {
		Resource *Resource
		Ok       bool
	}{
		{
			Resource: &Resource{URL: "/test"},
			Ok:       true,
		},
		{
			Resource: &Resource{URL: "/test", Methods: []string{"GET"}},
			Ok:       true,
		},
		{
			Resource: &Resource{},
		},
		{
			Resource: &Resource{URL: "/oauth"},
		},
		{
			Resource: &Resource{
				URL:     "/test",
				Methods: []string{"NO_SUCH_METHOD"},
			},
		},
	}

	for i, c := range testCases {
		err := c.Resource.valid()
		if err != nil && c.Ok {
			t.Errorf("case %d should not have failed", i)
		}
	}
}

func TestResourceString(t *testing.T) {
	resource := &Resource{
		Roles: []string{"1", "2", "3"},
	}
	if s := resource.String(); s == "" {
		t.Error("we should have recieved a string")
	}
}

func TestGetRoles(t *testing.T) {
	resource := &Resource{
		Roles: []string{"1", "2", "3"},
	}

	if resource.getRoles() != "1,2,3" {
		t.Error("the resource roles not as expected")
	}
}
