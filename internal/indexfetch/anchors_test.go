// Copyright © 2026 Meroxa, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package indexfetch

import "testing"

// The embedded default anchors MUST be the production ceremony keys, so a
// normal Action invocation verifies the real served index. Pinned so an
// accidental/malicious swap of trustanchors/anchors.json fails CI.
const (
	ceremonyRootKeyID      = "sha256:d657c2717760931c3771ec151e88fc143642b5c73ce79a3665fbf0f37f009795"
	ceremonyFreshnessKeyID = "sha256:50bfd2c15ecf3cfa41a220a6a5ab9711309751bbb84688fa574cd05d6b9cf783"
)

func TestLoadTrustAnchors_EmptyDefaultsToCeremonyAnchors(t *testing.T) {
	a, err := LoadTrustAnchors(nil)
	if err != nil {
		t.Fatalf("LoadTrustAnchors(nil): %v", err)
	}
	if _, ok := a.Roots[ceremonyRootKeyID]; !ok {
		t.Fatalf("embedded default missing ceremony root %s; got roots %v", ceremonyRootKeyID, keys(a.Roots))
	}
	if _, ok := a.Freshness[ceremonyFreshnessKeyID]; !ok {
		t.Fatalf("embedded default missing ceremony freshness %s", ceremonyFreshnessKeyID)
	}
	if len(a.Roots) != 1 || len(a.Freshness) != 1 {
		t.Fatalf("want exactly 1 root + 1 freshness anchor, got %d/%d", len(a.Roots), len(a.Freshness))
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
