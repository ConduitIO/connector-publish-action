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

// Package trustcore_test is this Action's north-star security-warranty
// test (deliverables §"Tests" in the PR-3 task): it proves that what this
// Action's composite steps would emit — a cosign-keyless signature bundle
// and a SLSA provenance attestation, both signed under this run's resolved
// Fulcio SAN — verifies successfully against
// github.com/conduitio/conduit/pkg/registry/trust's REAL, unmodified
// verification functions (the same ones `conduit connectors install`
// calls) when the identity matches the pin this Action would assemble on
// first registration; and that the headline fork attack — a valid,
// Rekor-logged signature from a DIFFERENT repository's identity — is
// refused with trust.ErrIdentityMismatch, never silently accepted and
// never misreported as trust.ErrUnsigned (which would suggest "nobody
// signed this" instead of the true "someone signed this, just not who you
// pinned").
//
// This is a documented, runnable test harness in the sense
// step4-publishing-action.md's test plan allows in lieu of a full live
// E2E against the real (not-yet-built) index-repo CI: it does not shell
// out to cosign or GitHub Actions, but it DOES exercise the actual
// production Sigstore verification code path via sigstore-go's own
// official offline test harness (github.com/sigstore/sigstore-go/pkg/
// testing/ca.VirtualSigstore — the exact same harness
// pkg/registry/trust/adversarial's shared corpus uses), so "would verify"
// here means the real cryptographic and identity-matching logic ran, not
// a mock of it.
package trustcore_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"encoding/json"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"

	conduitindex "github.com/conduitio/conduit/pkg/registry/index"
	"github.com/conduitio/conduit/pkg/registry/trust"

	"github.com/ConduitIO/connector-publish-action/internal/identity"
	"github.com/ConduitIO/connector-publish-action/internal/routing"
)

const (
	oidcIssuer = "https://token.actions.githubusercontent.com"

	// legitWorkflowRef is exactly the github.workflow_ref context value a
	// tag-triggered run of ConduitIO/conduit-connector-postgres's
	// publish.yml would present — this test's stand-in for "this Action
	// ran inside the legitimate connector repo's own job" (composite
	// action, not a reusable workflow — see identity package doc comment).
	legitWorkflowRef = "ConduitIO/conduit-connector-postgres/.github/workflows/publish.yml@refs/tags/v0.14.1"

	// forkWorkflowRef: an attacker forks the reference workflow into their
	// own repo and tags a release, publishing under the SAME connector
	// name ("postgres"). Same workflow file NAME, different owner/repo —
	// exactly step4-publishing-action.md §5's headline fork-attack row.
	forkWorkflowRef = "AttackerOrg/conduit-connector-postgres-totally-legit/.github/workflows/publish.yml@refs/tags/v0.14.1"

	firstRegistrationRefPattern = `refs/tags/v[0-9]+\.[0-9]+\.[0-9]+`
)

var artifactBytes = []byte("pretend this is the conduit-connector-postgres_0.14.1_linux_amd64 binary")

func TestE2E_LegitimatePublisherVerifies_ForkIsRefused(t *testing.T) {
	digest := sha256.Sum256(artifactBytes)

	// --- Step 1: this Action's identity package computes the resolved SAN
	// and, on first registration, assembles the expectedIdentityPattern
	// exactly as cmd/registry-pr would. ---
	legitParts, err := identity.ParseWorkflowRef(legitWorkflowRef)
	if err != nil {
		t.Fatalf("ParseWorkflowRef(legit): %v", err)
	}
	pinnedPattern, warnings, err := identity.AssemblePattern(legitParts, firstRegistrationRefPattern)
	if err != nil {
		t.Fatalf("AssemblePattern: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings for a tag-scoped pattern, got %v", warnings)
	}
	pinnedIdentity := trust.PinnedIdentity{OIDCIssuer: oidcIssuer, IdentityPattern: pinnedPattern}

	// --- Step 2: a single in-memory Fulcio CA + Rekor log stands in for
	// GitHub's real OIDC->Fulcio->Rekor pipeline. BOTH the legitimate
	// publisher and the attacker sign through the SAME CA/log — modeling
	// "the attacker's signature is completely real, cryptographically
	// valid, and validly Rekor-logged; the only thing wrong with it is
	// WHO signed it", per step4 §5's fork-attack row ("Cosign signs
	// successfully; Rekor logs the entry; the signature is
	// cryptographically valid"). ---
	virtualCA, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	trustedRoot, err := root.NewTrustedRoot(
		root.TrustedRootMediaType01,
		virtualCA.FulcioCertificateAuthorities(),
		virtualCA.CTLogs(),
		virtualCA.TimestampingAuthorities(),
		virtualCA.RekorLogs(),
	)
	if err != nil {
		t.Fatalf("NewTrustedRoot: %v", err)
	}

	legitSAN := legitParts.SAN()
	legitEntity, err := virtualCA.Sign(legitSAN, oidcIssuer, artifactBytes)
	if err != nil {
		t.Fatalf("signing as the legitimate publisher: %v", err)
	}

	forkParts, err := identity.ParseWorkflowRef(forkWorkflowRef)
	if err != nil {
		t.Fatalf("ParseWorkflowRef(fork): %v", err)
	}
	forkSAN := forkParts.SAN()
	forkEntity, err := virtualCA.Sign(forkSAN, oidcIssuer, artifactBytes)
	if err != nil {
		t.Fatalf("signing as the forked attacker: %v", err)
	}

	// --- Step 3: the legitimate signature verifies against
	// pkg/registry/trust's REAL VerifySignedEntitySignature — the same
	// function registry.TrustedVerifier.VerifyArtifact calls in
	// production. ---
	verifiedIdentity, err := trust.VerifySignedEntitySignature(legitEntity, digest[:], pinnedIdentity, trustedRoot)
	if err != nil {
		t.Fatalf("expected the legitimate publisher's signature to verify, got: %v", err)
	}
	if verifiedIdentity != legitSAN {
		t.Fatalf("verified identity %q does not equal the legitimate SAN %q", verifiedIdentity, legitSAN)
	}

	// --- Step 4: the fork's signature — cryptographically valid, validly
	// Rekor-logged, under the SAME trust root — is refused specifically
	// with trust.ErrIdentityMismatch, never trust.ErrUnsigned. This is the
	// headline assertion of this test. ---
	_, err = trust.VerifySignedEntitySignature(forkEntity, digest[:], pinnedIdentity, trustedRoot)
	if err == nil {
		t.Fatal("expected the forked repository's signature to be REFUSED, but it verified")
	}
	if !errors.Is(err, trust.ErrIdentityMismatch) {
		t.Fatalf("expected trust.ErrIdentityMismatch, got: %v", err)
	}
	if errors.Is(err, trust.ErrUnsigned) {
		t.Fatal("a valid-signature-wrong-identity refusal must never also classify as ErrUnsigned (would misleadingly read as \"nobody signed this\")")
	}

	// --- Step 5: this Action's OWN preflight (routing.Decide) independently
	// agrees — proving the defense operates at this Action's layer too, not
	// only deep inside pkg/registry/trust. ---
	indexWithLegitPin := legitIndexPayload(pinnedPattern)
	_, err = routing.Decide(indexWithLegitPin, true, "postgres", forkSAN, routing.RunnerGitHubHosted)
	var mismatch *routing.IdentityMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected routing.Decide to refuse the fork's resolved SAN with IdentityMismatchError, got: %v (kind unknown)", err)
	}

	// And the legitimate SAN routes as a clean version bump against the
	// same pinned index entry.
	decision, err := routing.Decide(indexWithLegitPin, true, "postgres", legitSAN, routing.RunnerGitHubHosted)
	if err != nil {
		t.Fatalf("expected the legitimate SAN to route cleanly, got: %v", err)
	}
	if decision.Kind != routing.KindVersionBump || !decision.AutoMerge {
		t.Fatalf("expected an automerge-eligible version bump, got %+v", decision)
	}

	// --- Step 6: SLSA provenance — subject digest + builder.id binding —
	// signed by the legitimate identity verifies via
	// trust.CheckProvenanceBinding using the REAL production
	// trust.ExpectedBuilderID constant; a provenance statement asserting a
	// DIFFERENT builder is refused with trust.ErrProvenanceInvalid. ---
	goodBody := slsaStatement(t, hex.EncodeToString(digest[:]), trust.ExpectedBuilderID)
	goodAttestEntity, err := virtualCA.Attest(legitSAN, oidcIssuer, goodBody)
	if err != nil {
		t.Fatalf("attesting valid provenance: %v", err)
	}
	stmt, err := trust.VerifySignedEntityAttestation(goodAttestEntity, pinnedIdentity, trustedRoot)
	if err != nil {
		t.Fatalf("expected valid provenance attestation to verify, got: %v", err)
	}
	if err := trust.CheckProvenanceBinding(stmt, digest, trust.ExpectedBuilderID); err != nil {
		t.Fatalf("expected CheckProvenanceBinding to accept matching subject+builder, got: %v", err)
	}

	badBody := slsaStatement(t, hex.EncodeToString(digest[:]), "https://example.com/some-other-untrusted-builder")
	badAttestEntity, err := virtualCA.Attest(legitSAN, oidcIssuer, badBody)
	if err != nil {
		t.Fatalf("attesting builder-mismatch provenance: %v", err)
	}
	stmt2, err := trust.VerifySignedEntityAttestation(badAttestEntity, pinnedIdentity, trustedRoot)
	if err != nil {
		t.Fatalf("attestation envelope itself is validly signed and should verify cryptographically: %v", err)
	}
	if err := trust.CheckProvenanceBinding(stmt2, digest, trust.ExpectedBuilderID); !errors.Is(err, trust.ErrProvenanceInvalid) {
		t.Fatalf("expected trust.ErrProvenanceInvalid for a builder.id mismatch, got: %v", err)
	}
}

func legitIndexPayload(pinnedPattern string) *conduitindex.Payload {
	return &conduitindex.Payload{
		SchemaVersion: 1,
		Connectors: []conduitindex.Connector{
			{
				Name: "postgres",
				Publisher: conduitindex.Publisher{
					ExpectedOIDCIssuer:      oidcIssuer,
					ExpectedIdentityPattern: pinnedPattern,
				},
				Versions: []conduitindex.ConnectorVersion{
					{Version: "0.14.0", MinConduitVersion: "0.15.0", MinProtocolVersion: "0.9.0"},
				},
			},
		},
	}
}

func slsaStatement(t *testing.T, subjectDigestHex, builderID string) []byte {
	t.Helper()
	stmt := map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []map[string]any{
			{"name": "conduit-connector-postgres", "digest": map[string]string{"sha256": subjectDigestHex}},
		},
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": map[string]any{
			"runDetails": map[string]any{
				"builder": map[string]any{"id": builderID},
			},
		},
	}
	b, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshaling SLSA statement: %v", err)
	}
	return b
}
