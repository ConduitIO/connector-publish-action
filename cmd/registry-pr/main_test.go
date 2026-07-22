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

// Black-box, in-process integration tests for the registry-pr CLI: they
// serve a REAL, ed25519-signed index (verified through
// github.com/conduitio/conduit/pkg/registry/index.Verify, the identical
// code path `conduit connectors install` uses) over httptest, and drive
// run() exactly as action.yml's "plan" step would invoke the compiled
// binary. This is step4-publishing-action.md §6's acceptance criteria
// 2/3/4, exercised end-to-end through this command rather than through
// routing/prbuild's unit tests in isolation.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	conduitindex "github.com/conduitio/conduit/pkg/registry/index"
)

const (
	oidcIssuer            = "https://token.actions.githubusercontent.com"
	postgresPinnedPattern = `^https://github\.com/ConduitIO/conduit-connector-postgres/\.github/workflows/publish\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$`
)

// signedIndexServer serves a real, verifiably root-signed index containing
// exactly one connector ("postgres", pinned to postgresPinnedPattern), and
// returns the trust-anchors JSON file path a caller passes via
// --trust-anchors-json to accept it.
func signedIndexServer(t *testing.T) (server *httptest.Server, anchorsPath string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating root key: %v", err)
	}
	keyID, err := conduitindex.KeyID(pub)
	if err != nil {
		t.Fatalf("computing keyId: %v", err)
	}

	payload := conduitindex.Payload{
		SchemaVersion: 1,
		Index:         conduitindex.IndexMeta{Version: 1, Timestamp: time.Now().UTC()},
		Connectors: []conduitindex.Connector{
			{
				Name: "postgres",
				Publisher: conduitindex.Publisher{
					ExpectedOIDCIssuer:      oidcIssuer,
					ExpectedIdentityPattern: postgresPinnedPattern,
				},
				Versions: []conduitindex.ConnectorVersion{
					{Version: "0.14.0", MinConduitVersion: "0.15.0", MinProtocolVersion: "0.9.0"},
				},
			},
		},
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshaling payload: %v", err)
	}
	canonical, err := conduitindex.Canonicalize(payloadBytes)
	if err != nil {
		t.Fatalf("canonicalizing payload: %v", err)
	}
	sig := ed25519.Sign(priv, canonical)

	envelope := map[string]any{
		"payload": json.RawMessage(payloadBytes),
		"signatures": []map[string]any{
			{
				"role":      "root",
				"keyId":     keyID,
				"algorithm": "ed25519",
				"signature": base64.StdEncoding.EncodeToString(sig),
			},
		},
	}
	envelopeBytes, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshaling envelope: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(envelopeBytes)
	}))
	t.Cleanup(srv.Close)

	anchors := map[string]any{
		"roots": map[string]string{keyID: base64.StdEncoding.EncodeToString(pub)},
	}
	anchorsBytes, err := json.Marshal(anchors)
	if err != nil {
		t.Fatalf("marshaling anchors: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "anchors.json")
	if err := os.WriteFile(path, anchorsBytes, 0o600); err != nil {
		t.Fatalf("writing anchors file: %v", err)
	}

	return srv, path
}

func readPRMeta(t *testing.T, outputDir string) planResult {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(outputDir, "pr-meta.json"))
	if err != nil {
		t.Fatalf("reading pr-meta.json: %v", err)
	}
	var result planResult
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatalf("parsing pr-meta.json: %v", err)
	}
	return result
}

func baseArgs(t *testing.T, indexURL, anchorsPath, outputDir string) []string {
	t.Helper()
	return []string{
		"-min-conduit-version", "0.15.0",
		"-min-protocol-version", "0.9.0",
		"-build-matrix-json", `[{"os":"linux","arch":"amd64","kind":"standalone","url":"https://example.com/a","sha256":"` + zeroSHA + `","size":100,"signatureBundleURL":"https://example.com/a.sigstore.json"}]`,
		"-provenance-bundle-url", "https://example.com/provenance.sigstore.json",
		"-index-json-url", indexURL,
		"-trust-anchors-json", anchorsPath,
		"-output-dir", outputDir,
	}
}

const zeroSHA = "0000000000000000000000000000000000000000000000000000000000000000000000000000"

func TestRun_NewNameRegistration(t *testing.T) {
	srv, anchorsPath := signedIndexServer(t)
	outputDir := t.TempDir()

	args := append(baseArgs(t, srv.URL, anchorsPath, outputDir),
		"-workflow-ref", "ConduitIO/conduit-connector-kafka/.github/workflows/publish.yml@refs/tags/v1.0.0",
		"-connector-name", "kafka",
		"-version", "1.0.0",
		"-display-name", "Kafka",
		"-repository", "https://github.com/ConduitIO/conduit-connector-kafka",
		"-first-registration-ref-pattern", `refs/tags/v[0-9]+\.[0-9]+\.[0-9]+`,
	)

	if err := run(args); err != nil {
		t.Fatalf("run() returned an error for a legitimate new-name registration: %v", err)
	}

	result := readPRMeta(t, outputDir)
	if result.PRKind != "new-name" {
		t.Fatalf("expected prKind=new-name, got %q", result.PRKind)
	}
	if result.AutoMerge {
		t.Fatal("a new-name registration must never be automerge")
	}
	if len(result.Labels) != 1 || result.Labels[0] != "registry/new-registration" {
		t.Fatalf("expected exactly [registry/new-registration], got %v", result.Labels)
	}

	fileBytes, err := os.ReadFile(filepath.Join(outputDir, "index/connectors/kafka.json"))
	if err != nil {
		t.Fatalf("expected the connector file to be written: %v", err)
	}
	var connector conduitindex.Connector
	if err := json.Unmarshal(fileBytes, &connector); err != nil {
		t.Fatalf("connector file does not parse: %v", err)
	}
	if connector.Publisher.ExpectedIdentityPattern == "" {
		t.Fatal("expected an assembled expectedIdentityPattern")
	}
	// The assembled pattern must match this run's own SAN and reject a
	// same-name fork under a different owner.
	ok, err := regexpMatch(connector.Publisher.ExpectedIdentityPattern, "https://github.com/ConduitIO/conduit-connector-kafka/.github/workflows/publish.yml@refs/tags/v1.0.0")
	if err != nil || !ok {
		t.Fatalf("assembled pattern does not match own SAN: ok=%v err=%v", ok, err)
	}
	ok, err = regexpMatch(connector.Publisher.ExpectedIdentityPattern, "https://github.com/AttackerOrg/conduit-connector-kafka/.github/workflows/publish.yml@refs/tags/v1.0.0")
	if err != nil || ok {
		t.Fatalf("assembled pattern must not match a forked owner: ok=%v err=%v", ok, err)
	}
}

func TestRun_NewNameRegistration_RequiresRefPattern(t *testing.T) {
	srv, anchorsPath := signedIndexServer(t)
	outputDir := t.TempDir()

	args := append(baseArgs(t, srv.URL, anchorsPath, outputDir),
		"-workflow-ref", "ConduitIO/conduit-connector-kafka/.github/workflows/publish.yml@refs/tags/v1.0.0",
		"-connector-name", "kafka",
		"-version", "1.0.0",
	)
	if err := run(args); err == nil {
		t.Fatal("expected run() to refuse a new-name registration with no --first-registration-ref-pattern")
	}
}

func TestRun_VersionBump_MatchingIdentity(t *testing.T) {
	srv, anchorsPath := signedIndexServer(t)
	outputDir := t.TempDir()

	args := append(baseArgs(t, srv.URL, anchorsPath, outputDir),
		"-workflow-ref", "ConduitIO/conduit-connector-postgres/.github/workflows/publish.yml@refs/tags/v0.14.1",
		"-connector-name", "postgres",
		"-version", "0.14.1",
	)
	if err := run(args); err != nil {
		t.Fatalf("run() returned an error for a legitimate version bump: %v", err)
	}

	result := readPRMeta(t, outputDir)
	if result.PRKind != "version-bump" {
		t.Fatalf("expected prKind=version-bump, got %q", result.PRKind)
	}
	if !result.AutoMerge {
		t.Fatal("expected a matching-identity, github-hosted version bump to be automerge-eligible")
	}

	fileBytes, err := os.ReadFile(filepath.Join(outputDir, "index/connectors/postgres.json"))
	if err != nil {
		t.Fatalf("expected the connector file to be written: %v", err)
	}
	var connector conduitindex.Connector
	if err := json.Unmarshal(fileBytes, &connector); err != nil {
		t.Fatalf("connector file does not parse: %v", err)
	}
	if connector.Publisher.ExpectedIdentityPattern != postgresPinnedPattern {
		t.Fatalf("publisher pin must be untouched by a version bump: got %q", connector.Publisher.ExpectedIdentityPattern)
	}
	if len(connector.Versions) != 2 {
		t.Fatalf("expected exactly one appended version (2 total), got %d", len(connector.Versions))
	}
}

// TestRun_ForkAttack_IsRefused is this command's own end-to-end proof of
// the headline fork-attack defense (step4 §5 / §6 AC-4): a run whose
// resolved identity does not match the pinned pattern for an EXISTING
// name must fail the run itself, before any PR content is written to disk.
func TestRun_ForkAttack_IsRefused(t *testing.T) {
	srv, anchorsPath := signedIndexServer(t)
	outputDir := t.TempDir()

	args := append(baseArgs(t, srv.URL, anchorsPath, outputDir),
		"-workflow-ref", "AttackerOrg/conduit-connector-postgres-totally-legit/.github/workflows/publish.yml@refs/tags/v0.14.1",
		"-connector-name", "postgres",
		"-version", "0.14.1",
	)
	err := run(args)
	if err == nil {
		t.Fatal("expected run() to refuse the forked identity, got success")
	}

	result := readPRMeta(t, outputDir)
	if !result.Blocked {
		t.Fatal("expected pr-meta.json to record blocked=true")
	}
	if result.PRKind != "blocked-identity-mismatch" {
		t.Fatalf("expected prKind=blocked-identity-mismatch, got %q", result.PRKind)
	}
	if result.BlockReason == "" {
		t.Fatal("expected a non-empty, actionable blockReason")
	}

	if _, statErr := os.Stat(filepath.Join(outputDir, "index/connectors/postgres.json")); statErr == nil {
		t.Fatal("no connector file must be written when the run is blocked")
	}
}

func TestRun_SelfHostedRunner_ForcesHumanReview(t *testing.T) {
	srv, anchorsPath := signedIndexServer(t)
	outputDir := t.TempDir()

	args := append(baseArgs(t, srv.URL, anchorsPath, outputDir),
		"-workflow-ref", "ConduitIO/conduit-connector-postgres/.github/workflows/publish.yml@refs/tags/v0.14.1",
		"-connector-name", "postgres",
		"-version", "0.14.1",
		"-runner-environment", "self-hosted",
	)
	if err := run(args); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result := readPRMeta(t, outputDir)
	if result.AutoMerge {
		t.Fatal("a self-hosted-runner build must never be automerge, even with a matching identity")
	}
	found := false
	for _, l := range result.Labels {
		if l == "registry/human-review-required" {
			found = true
		}
		if l == "automerge" {
			t.Fatal("automerge label must not be present for a self-hosted build")
		}
	}
	if !found {
		t.Fatalf("expected the forced human-review label, got %v", result.Labels)
	}
}

func regexpMatch(pattern, s string) (bool, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, err
	}
	return re.MatchString(s), nil
}
