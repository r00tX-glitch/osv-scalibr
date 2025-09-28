// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package elasticcloudapikey_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/elasticcloudapikey"
)

const (
	validatorTestKey = "essu_UkdOdllWaEthMEpKVURjM1pqaHpaekpaUzJjNlNsOTVWM2hhVmw5aU9EVTVXbDlKVkhacmRsQk1VUT09AAAAAH7kRWQ="
)

// mockTransport redirects requests to the test server for the configured hosts.
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if req.URL.Host == "api.elastic-cloud.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockAPIServer creates a mock Elastic Cloud API server for testing the validator.
func mockAPIServer(t *testing.T, expectedKey string, statusCode int, body any) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Expect a GET to /api/v1/account
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/account" {
			t.Errorf("unexpected request: %s %s, expected: GET /api/v1/account", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Authorization header contains the expected key
		authHeader := r.Header.Get("Authorization")
		expectedHeader := "ApiKey " + expectedKey
		if expectedKey != "" && authHeader != expectedHeader {
			t.Errorf("expected Authorization header to be %q, got: %q", expectedHeader, authHeader)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		body       any
		want       veles.ValidationStatus
		wantErr    error
	}{
		{
			name:       "valid_key",
			statusCode: http.StatusOK,
			body: map[string]any{
				"name": "test",
				"id":   "1234",
			},
			want: veles.ValidationValid,
		},
		{
			name:       "invalid_key_unauthorized",
			statusCode: http.StatusUnauthorized,
			body: map[string]any{
				"error": "invalid authentication credentials",
			},
			want: veles.ValidationInvalid,
		},
		{
			name:       "server_error",
			statusCode: http.StatusInternalServerError,
			body:       nil,
			want:       veles.ValidationFailed,
			wantErr:    cmpopts.AnyError,
		},
		{
			name:       "forbidden_error",
			statusCode: http.StatusForbidden,
			body:       nil,
			want:       veles.ValidationFailed,
			wantErr:    cmpopts.AnyError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock server
			server := mockAPIServer(t, validatorTestKey, tc.statusCode, tc.body)
			defer server.Close()

			// Create client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create validator with mock client
			validator := elasticcloudapikey.NewValidator(
				elasticcloudapikey.WithClient(client),
			)

			// Create test key
			key := elasticcloudapikey.ElasticCloudAPIKey{Key: validatorTestKey}

			// Test validation
			got, err := validator.Validate(context.Background(), key)

			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Validate() error mismatch (-want +got):\n%s", diff)
			}

			// Check validation status
			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidator_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(nil)
	t.Cleanup(func() {
		server.Close()
	})

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := elasticcloudapikey.NewValidator(
		elasticcloudapikey.WithClient(client),
	)

	key := elasticcloudapikey.ElasticCloudAPIKey{Key: validatorTestKey}

	// Create context that is immediately cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Test validation with cancelled context
	got, err := validator.Validate(ctx, key)

	if diff := cmp.Diff(cmpopts.AnyError, err, cmpopts.EquateErrors()); diff != "" {
		t.Errorf("Validate() error mismatch (-want +got):\n%s", diff)
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}

func TestValidator_InvalidRequest(t *testing.T) {
	// For Elastic validator, an "invalid" key is communicated via 401 status.
	server := mockAPIServer(t, "", http.StatusUnauthorized, map[string]any{
		"error": "invalid authentication credentials",
	})
	defer server.Close()

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := elasticcloudapikey.NewValidator(
		elasticcloudapikey.WithClient(client),
	)

	testCases := []struct {
		name     string
		key      string
		expected veles.ValidationStatus
	}{
		{
			name:     "empty_key",
			key:      "",
			expected: veles.ValidationInvalid,
		},
		{
			name:     "invalid_key_format",
			key:      "invalid-api-key-format",
			expected: veles.ValidationInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			k := elasticcloudapikey.ElasticCloudAPIKey{Key: tc.key}

			got, err := validator.Validate(context.Background(), k)

			if err != nil {
				t.Errorf("Validate() unexpected error for %s: %v", tc.name, err)
			}
			if got != tc.expected {
				t.Errorf("Validate() = %v, want %v for %s", got, tc.expected, tc.name)
			}
		})
	}
}
