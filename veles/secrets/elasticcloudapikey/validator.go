// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package elasticcloudapikey

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/osv-scalibr/veles"
)

var (
	// Ensure constructors satisfy the interface at compile time.
	_ veles.Validator[ElasticCloudAPIKey] = &Validator{}
)

// Endpoint used for validation.
const (
	apiEndpoint = "https://api.elastic-cloud.com/api/v1/account"
)

// Validator validates Elastic Cloud API keys.
type Validator struct {
	httpC *http.Client
}

// ValidatorOption configures a Validator when creating it via New.
type ValidatorOption func(*Validator)

// WithClient configures the http.Client used by Validator.
// By default it uses http.DefaultClient.
func WithClient(c *http.Client) ValidatorOption {
	return func(v *Validator) {
		v.httpC = c
	}
}

// NewValidator creates a new Validator with the given options.
func NewValidator(opts ...ValidatorOption) *Validator {
	v := &Validator{
		httpC: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given ElasticCloudAPIKey is valid.
//
// It calls GET https://api.elastic-cloud.com/api/v1/account with header "Authorization: ApiKey <key>".
// - 200 OK  -> authenticated and valid.
// - 401     -> invalid API key (authentication failure).
// - other   -> validation failed (unexpected response).
func (v *Validator) Validate(ctx context.Context, key ElasticCloudAPIKey) (veles.ValidationStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiEndpoint, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	req.Header.Set("Authorization", "ApiKey "+key.Key)

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to GET %q: %w", apiEndpoint, err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		// 200 OK => the key is valid and authenticated.
		return veles.ValidationValid, nil

	case http.StatusUnauthorized:
		// 401 => authentication failed -> invalid key.
		return veles.ValidationInvalid, nil
	default:
		// other status codes considered as validation failed.
		return veles.ValidationFailed, fmt.Errorf("unexpected status %q from %q", res.Status, apiEndpoint)
	}
}
