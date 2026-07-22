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

// Package indexfetch fetches the current index and verifies it through the
// EXACT SAME code path `conduit connectors install` uses
// (github.com/conduitio/conduit/pkg/registry/index.Verify) — step4
// §3's opening sentence: "the Action itself never trusts an unverified
// index when deciding what kind of PR to open". This package never
// implements its own parsing/verification logic; it is a thin
// fetch-then-call-the-shared-library wrapper, by design (plan-v2 §2.1's
// rationale for pkg/registry/index being a public, cross-repo-imported
// package).
package indexfetch

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	conduitindex "github.com/conduitio/conduit/pkg/registry/index"
)

// MaxIndexBytes mirrors pkg/registry/boundedfetch's index cap (P0-2):
// generous for a dozens-to-low-hundreds-of-connectors catalog.
const MaxIndexBytes = 8 << 20 // 8 MiB

// Fetch retrieves raw index bytes from url, bounded to MaxIndexBytes —
// mirroring pkg/registry/boundedfetch.FetchBounded's "read maxBytes+1,
// distinguish truly-oversized from exactly-at-the-cap" behavior so this
// Action's own resource-bound posture matches the client's.
func Fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("indexfetch: building request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("indexfetch: fetching %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("indexfetch: fetching %s: unexpected status %d", url, resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, MaxIndexBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("indexfetch: reading body of %s: %w", url, err)
	}
	if int64(len(raw)) > MaxIndexBytes {
		return nil, fmt.Errorf("indexfetch: index at %s exceeds %d byte cap", url, MaxIndexBytes)
	}
	return raw, nil
}

// FetchAndVerify fetches url and verifies it via conduitindex.Verify against
// anchors, returning the VerifiedIndex only when Verified is true. Callers
// (routing.Decide) must never proceed with a result whose Verified field is
// false — this function already refuses to return one, as a second,
// belt-and-suspenders check on top of conduitindex.Verify's own contract.
//
// lastVerifiedConnectorsHash is normally empty: unlike `conduit connectors
// install`, this Action is stateless across runs (a fresh checkout every
// time) and has no persisted high-water mark of a previously root-verified
// connectors[] hash. Per index.Verify's own contract, a freshness-only
// signature can never be accepted with an empty hash (R-1 §b: "a
// freshness-only index can never be the FIRST index a client ever
// accepts"), so this Action can only route against an index whose latest
// signature is root-signed. If the index happens to be in a freshness-only
// heartbeat state (content unchanged since the last root sign, only
// index.timestamp extended), this call fails closed with
// CodeIndexIntegrity until a root re-sign occurs — a real, documented
// limitation (see README "Known limitations"), not silently papered over
// by accepting an unverified index.
func FetchAndVerify(ctx context.Context, url string, anchors conduitindex.TrustAnchors, lastVerifiedConnectorsHash string) (*conduitindex.VerifiedIndex, error) {
	raw, err := Fetch(ctx, url)
	if err != nil {
		return nil, err
	}
	vi, err := conduitindex.Verify(raw, anchors, lastVerifiedConnectorsHash)
	if err != nil {
		return nil, fmt.Errorf("indexfetch: index at %s failed verification: %w", url, err)
	}
	if !vi.Verified {
		// Should be unreachable — conduitindex.Verify's own contract is to
		// return an error whenever it cannot set Verified true. Refuse
		// anyway rather than trust a zero-value/ambiguous result.
		return nil, fmt.Errorf("indexfetch: index at %s parsed but did not verify", url)
	}
	return vi, nil
}

// anchorFile is the on-disk JSON shape LoadTrustAnchors reads: base64
// standard-encoded ed25519 public keys keyed by keyId
// ("sha256:<hex fingerprint>", matching conduitindex.KeyID). This lets an
// operator (or a test) supply anchors explicitly — see this package's doc
// comment and the README's "trust-anchors-json" input for why: production
// root/freshness key material does not exist in
// github.com/conduitio/conduit yet (pkg/registry/index/anchors.go: "No key
// material exists yet: it is generated during the bootstrap ceremony,
// plan-v2 §9") — until that ceremony ships real embedded anchors, this
// Action's index-verify step fails closed (CodeTrustAnchorExpired) against
// the zero-value TrustAnchors{} default, which is the CORRECT behavior,
// not a bug: there is nothing yet to trust.
type anchorFile struct {
	Roots     map[string]string `json:"roots"`
	Freshness map[string]string `json:"freshness"`
}

// LoadTrustAnchors parses path (see anchorFile) into a conduitindex.TrustAnchors.
// An empty path returns the zero value (no anchors) — Verify then fails
// closed with CodeTrustAnchorExpired, per this package's doc comment.
func LoadTrustAnchors(raw []byte) (conduitindex.TrustAnchors, error) {
	if len(raw) == 0 {
		return conduitindex.TrustAnchors{}, nil
	}
	var af anchorFile
	if err := json.Unmarshal(raw, &af); err != nil {
		return conduitindex.TrustAnchors{}, fmt.Errorf("indexfetch: parsing trust anchors file: %w", err)
	}
	roots, err := decodeKeys(af.Roots)
	if err != nil {
		return conduitindex.TrustAnchors{}, fmt.Errorf("indexfetch: decoding root anchors: %w", err)
	}
	freshness, err := decodeKeys(af.Freshness)
	if err != nil {
		return conduitindex.TrustAnchors{}, fmt.Errorf("indexfetch: decoding freshness anchors: %w", err)
	}
	return conduitindex.TrustAnchors{Roots: roots, Freshness: freshness}, nil
}

func decodeKeys(in map[string]string) (map[string]ed25519.PublicKey, error) {
	out := make(map[string]ed25519.PublicKey, len(in))
	for keyID, b64 := range in {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", keyID, err)
		}
		out[keyID] = ed25519.PublicKey(raw)
	}
	return out, nil
}
