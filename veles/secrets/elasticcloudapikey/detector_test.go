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
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/elasticcloudapikey"
)

const (
	// Example valid Elastic Cloud API key.
	detectorTestKey = "essu_UkdOdllWaEthMEpKVURjM1pqaHpaekpaUzJjNlNsOTVWM2hhVmw5aU9EVTVXbDlKVkhacmRsQk1VUT09AAAAAH7kRWQ="
)

// TestDetector_TruePositives tests for true positives.
func TestDetector_TruePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{elasticcloudapikey.NewDetector()},
	)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: detectorTestKey,
		want: []veles.Secret{
			elasticcloudapikey.ElasticCloudAPIKey{Key: detectorTestKey},
		},
	}, {
		name:  "match at end of string",
		input: `ELASTIC_KEY=` + detectorTestKey,
		want: []veles.Secret{
			elasticcloudapikey.ElasticCloudAPIKey{Key: detectorTestKey},
		},
	}, {
		name:  "match in quotes",
		input: `key="` + detectorTestKey + `"`,
		want: []veles.Secret{
			elasticcloudapikey.ElasticCloudAPIKey{Key: detectorTestKey},
		},
	}, {
		name:  "multiple matches",
		input: detectorTestKey + "\n" + detectorTestKey,
		want: []veles.Secret{
			elasticcloudapikey.ElasticCloudAPIKey{Key: detectorTestKey},
			elasticcloudapikey.ElasticCloudAPIKey{Key: detectorTestKey},
		},
	}, {
		name: "larger input containing key",
		input: fmt.Sprintf("config:\n  api_key: %s\n",
			detectorTestKey),
		want: []veles.Secret{
			elasticcloudapikey.ElasticCloudAPIKey{Key: detectorTestKey},
		},
	}, {
		name:  "potential match longer than max key length",
		input: detectorTestKey + "EXTRA",
		want: []veles.Secret{
			elasticcloudapikey.ElasticCloudAPIKey{Key: detectorTestKey},
		},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(),
				strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got,
				cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s",
					diff)
			}
		})
	}
}

// TestDetector_TrueNegatives tests for false negatives.
func TestDetector_TrueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{elasticcloudapikey.NewDetector()},
	)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "empty input",
		input: "",
	}, {
		name:  "short key should not match",
		input: detectorTestKey[:len(detectorTestKey)-5],
	}, {
		name: "invalid character in key should not match",
		input: "essu_" + strings.ReplaceAll(
			detectorTestKey[5:], "a", "!",
		),
	}, {
		name:  "incorrect prefix should not match",
		input: "essv_" + detectorTestKey[5:],
	}, {
		name:  "prefix missing dash should not match",
		input: "essu" + detectorTestKey[5:], // removes the dash
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(),
				strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got,
				cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s",
					diff)
			}
		})
	}
}
