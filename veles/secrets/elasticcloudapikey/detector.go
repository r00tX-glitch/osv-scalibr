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

package elasticcloudapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// Ensure constructors satisfy the interface at compile time.
	_ veles.Detector = NewDetector()
)

// Pattern: "essu_" + 91 base64 chars + "=" OR "essu_" + 92 base64 chars.
// The length of the key is 4 (essu_) + 92 = 96, or 4 + 91 + 1 = 96.
const keyMaxLen = 100 // A bit of buffer

var keyRe = regexp.MustCompile(`essu_([A-Za-z0-9+/]{91}=|[A-Za-z0-9+/]{92})`)

// NewDetector returns a detector for Elastic Cloud API keys.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: keyMaxLen,
		Re:     keyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return ElasticCloudAPIKey{Key: string(b)}, true
		},
	}
}
