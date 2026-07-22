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

package routing_test

import (
	"errors"
	"testing"

	conduitindex "github.com/conduitio/conduit/pkg/registry/index"

	"github.com/ConduitIO/connector-publish-action/internal/routing"
)

const (
	oidcIssuer    = "https://token.actions.githubusercontent.com"
	pinnedPattern = `^https://github\.com/ConduitIO/conduit-connector-postgres/\.github/workflows/publish\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$`
	legitSAN      = "https://github.com/ConduitIO/conduit-connector-postgres/.github/workflows/publish.yml@refs/tags/v0.14.1"
	forkSAN       = "https://github.com/AttackerOrg/conduit-connector-postgres/.github/workflows/publish.yml@refs/tags/v0.14.1"
)

func fixturePayload() *conduitindex.Payload {
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

func TestDecide_RefusesUnverifiedIndex(t *testing.T) {
	_, err := routing.Decide(fixturePayload(), false, "postgres", legitSAN, routing.RunnerGitHubHosted)
	if err == nil {
		t.Fatal("expected Decide to refuse an unverified index")
	}
}

func TestDecide_NewName(t *testing.T) {
	d, err := routing.Decide(fixturePayload(), true, "kafka", legitSAN, routing.RunnerGitHubHosted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Kind != routing.KindNewName {
		t.Fatalf("got kind %q, want %q", d.Kind, routing.KindNewName)
	}
	if d.AutoMerge {
		t.Fatal("a new-name registration must NEVER be automerge")
	}
	assertLabels(t, d.Labels, routing.LabelNewRegistration)
	assertNoLabel(t, d.Labels, routing.LabelAutomerge)
}

func TestDecide_VersionBump_MatchingIdentity(t *testing.T) {
	d, err := routing.Decide(fixturePayload(), true, "postgres", legitSAN, routing.RunnerGitHubHosted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Kind != routing.KindVersionBump {
		t.Fatalf("got kind %q, want %q", d.Kind, routing.KindVersionBump)
	}
	if !d.AutoMerge {
		t.Fatal("a matching-identity, github-hosted version bump should be automerge-eligible")
	}
	if d.ExistingConnector == nil || d.ExistingConnector.Name != "postgres" {
		t.Fatalf("expected ExistingConnector to be populated, got %+v", d.ExistingConnector)
	}
	assertLabels(t, d.Labels, routing.LabelVersionBump, routing.LabelAutomerge)
}

// TestDecide_ForkAttack is the headline test: an attacker forks the
// reference workflow into a different repo and tags a release publishing
// under the EXISTING name "postgres". The resolved SAN is
// AttackerOrg/conduit-connector-postgres/... instead of
// ConduitIO/conduit-connector-postgres/... — Decide must refuse with
// IdentityMismatchError, and MUST NOT silently fall back to treating this
// as a new-name registration (which would let the attacker register their
// own pin) or as a successful version bump.
func TestDecide_ForkAttack(t *testing.T) {
	_, err := routing.Decide(fixturePayload(), true, "postgres", forkSAN, routing.RunnerGitHubHosted)
	if err == nil {
		t.Fatal("expected the fork attack to be refused, got a successful Decision")
	}
	var mismatch *routing.IdentityMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected *routing.IdentityMismatchError, got %T: %v", err, err)
	}
	if mismatch.ConnectorName != "postgres" || mismatch.ResolvedSAN != forkSAN {
		t.Fatalf("unexpected mismatch error contents: %+v", mismatch)
	}
}

func TestDecide_SelfHostedForcesHumanReview(t *testing.T) {
	d, err := routing.Decide(fixturePayload(), true, "postgres", legitSAN, routing.RunnerSelfHosted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.AutoMerge {
		t.Fatal("a self-hosted-runner version bump must never be automerge, even with a matching identity")
	}
	if !d.ForceHumanReview {
		t.Fatal("expected ForceHumanReview to be true for a self-hosted runner")
	}
	assertLabels(t, d.Labels, routing.LabelVersionBump, routing.LabelHumanReview)
	assertNoLabel(t, d.Labels, routing.LabelAutomerge)
}

// TestDecide_VersionBumpNeverTouchesPublisher is a structural check: even
// though ExistingConnector is returned, nothing about Decide's return value
// lets a caller widen the diff beyond versions[] — this is really testing
// prbuild.BuildVersionBump's contract (see prbuild_test.go), but recorded
// here too as living documentation of the invariant this package's callers
// depend on.
func TestDecide_VersionBumpNeverTouchesPublisher(t *testing.T) {
	d, err := routing.Decide(fixturePayload(), true, "postgres", legitSAN, routing.RunnerGitHubHosted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.ExistingConnector.Publisher.ExpectedIdentityPattern != pinnedPattern {
		t.Fatal("ExistingConnector's publisher pin must be untouched")
	}
}

func assertLabels(t *testing.T, got []string, want ...string) {
	t.Helper()
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if !set[w] {
			t.Fatalf("expected label %q in %v", w, got)
		}
	}
}

func assertNoLabel(t *testing.T, got []string, forbidden string) {
	t.Helper()
	for _, g := range got {
		if g == forbidden {
			t.Fatalf("label %q must not be present in %v", forbidden, got)
		}
	}
}
