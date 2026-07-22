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

package prbuild_test

import (
	"encoding/json"
	"strings"
	"testing"

	conduitindex "github.com/conduitio/conduit/pkg/registry/index"
	"github.com/google/go-cmp/cmp"

	"github.com/ConduitIO/connector-publish-action/internal/prbuild"
)

func existingConnector() conduitindex.Connector {
	return conduitindex.Connector{
		Name:        "postgres",
		DisplayName: "PostgreSQL",
		Description: "CDC source and destination for PostgreSQL",
		Repository:  "https://github.com/ConduitIO/conduit-connector-postgres",
		Publisher: conduitindex.Publisher{
			ExpectedOIDCIssuer:      "https://token.actions.githubusercontent.com",
			ExpectedIdentityPattern: `^https://github\.com/ConduitIO/conduit-connector-postgres/\.github/workflows/publish\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$`,
		},
		Versions: []conduitindex.ConnectorVersion{
			{Version: "0.14.0", MinConduitVersion: "0.15.0", MinProtocolVersion: "0.9.0"},
		},
	}
}

// TestBuildVersionBump_ScopeLimited is the structural proof of step4 §3.2
// step 3: appending a version must not change ANY other field, and must
// not touch prior versions[] entries.
func TestBuildVersionBump_ScopeLimited(t *testing.T) {
	existing := existingConnector()
	newVersion := conduitindex.ConnectorVersion{Version: "0.14.1", MinConduitVersion: "0.15.0", MinProtocolVersion: "0.9.0"}

	updated := prbuild.BuildVersionBump(existing, newVersion)

	if updated.Name != existing.Name ||
		updated.DisplayName != existing.DisplayName ||
		updated.Description != existing.Description ||
		updated.Repository != existing.Repository {
		t.Fatalf("non-versions[] field changed:\n got: %+v\nwant: %+v", updated, existing)
	}
	if diff := cmp.Diff(existing.Publisher, updated.Publisher); diff != "" {
		t.Fatalf("Publisher must be byte-identical after a version bump (-want +got):\n%s", diff)
	}
	if len(updated.Versions) != len(existing.Versions)+1 {
		t.Fatalf("expected exactly one appended version, got %d (had %d)", len(updated.Versions), len(existing.Versions))
	}
	if diff := cmp.Diff(existing.Versions[0], updated.Versions[0]); diff != "" {
		t.Fatalf("prior version entry must be untouched (-want +got):\n%s", diff)
	}
	if updated.Versions[len(updated.Versions)-1].Version != "0.14.1" {
		t.Fatalf("expected the new version to be appended, got %+v", updated.Versions)
	}

	// Mutating the returned slice must not alias the original — a defensive
	// check that BuildVersionBump copied rather than aliased the backing array.
	updated.Versions[0].Version = "TAMPERED"
	if existing.Versions[0].Version == "TAMPERED" {
		t.Fatal("BuildVersionBump must not alias the existing connector's Versions backing array")
	}
}

func TestBuildNewConnector(t *testing.T) {
	version := conduitindex.ConnectorVersion{Version: "1.0.0", MinConduitVersion: "0.15.0", MinProtocolVersion: "0.9.0"}
	c := prbuild.BuildNewConnector(prbuild.NewConnectorInput{
		Name:                    "kafka",
		DisplayName:             "Kafka",
		Description:             "desc",
		Repository:              "https://github.com/ConduitIO/conduit-connector-kafka",
		ExpectedOIDCIssuer:      "https://token.actions.githubusercontent.com",
		ExpectedIdentityPattern: `^https://github\.com/ConduitIO/conduit-connector-kafka/\.github/workflows/publish\.yml@refs/tags/v.*$`,
		Version:                 version,
	})
	if c.Name != "kafka" || len(c.Versions) != 1 || c.Versions[0].Version != "1.0.0" {
		t.Fatalf("unexpected connector: %+v", c)
	}
	if c.Publisher.ExpectedOIDCIssuer == "" || c.Publisher.ExpectedIdentityPattern == "" {
		t.Fatalf("expected publisher identity pin to be set: %+v", c.Publisher)
	}
}

func TestMarshalConnectorFile_RoundTrips(t *testing.T) {
	c := existingConnector()
	b, err := prbuild.MarshalConnectorFile(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var roundTripped conduitindex.Connector
	if err := json.Unmarshal(b, &roundTripped); err != nil {
		t.Fatalf("marshaled connector file does not parse as conduitindex.Connector: %v", err)
	}
	if diff := cmp.Diff(c, roundTripped); diff != "" {
		t.Fatalf("round-trip mismatch (-want +got):\n%s", diff)
	}
}

func TestNewRegistrationPRBody_NeverImpliesAutomerge(t *testing.T) {
	body := prbuild.NewRegistrationPRBody("kafka", "https://github.com/ConduitIO/conduit-connector-kafka/.github/workflows/publish.yml@refs/tags/v1.0.0", "builder-id", nil, "<!-- marker -->")
	if strings.Contains(body, "Labeled `automerge`") || strings.Contains(body, "labeled automerge") {
		t.Fatalf("new-registration PR body must never claim automerge was applied: %s", body)
	}
	if !strings.Contains(body, "must **never** carry `automerge`") {
		t.Fatal("expected the fixed 'must never carry automerge' notice")
	}
	if !strings.Contains(body, "Do not auto-merge") {
		t.Fatal("expected the fixed 'do not auto-merge' notice")
	}
}

func TestVersionBumpPRBody_SelfHostedCallsOutForcedReview(t *testing.T) {
	body := prbuild.VersionBumpPRBody("postgres", "0.14.1", "san", "builder-id", true, "<!-- marker -->")
	if !strings.Contains(body, "self-hosted runner") {
		t.Fatal("expected the self-hosted forced-review notice")
	}
	if strings.Contains(body, "Labeled `automerge`") {
		t.Fatal("self-hosted body must not claim the automerge label")
	}
}
