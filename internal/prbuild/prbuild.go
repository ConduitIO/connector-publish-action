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

// Package prbuild assembles the index-repo PR content and body text for
// both routing outcomes (conduit-registry-plans/step4-publishing-action.md
// §3). It never has access to anything that would let it construct a
// diff wider than what routing.Decide authorized: BuildVersionBump takes
// the ALREADY-VERIFIED existing connector.Connector and returns a copy
// with exactly one appended version — there is no code path in this
// package that can set/change Publisher, Name, DisplayName, Description,
// or Repository on a version-bump.
package prbuild

import (
	"encoding/json"
	"fmt"
	"strings"

	conduitindex "github.com/conduitio/conduit/pkg/registry/index"
)

// IdempotencyMarker is the hidden PR-body token (step4 §3.3) used to find
// and update an existing open PR instead of opening a duplicate one on
// workflow re-run. Not a security control.
func IdempotencyMarker(connectorName, version string) string {
	return fmt.Sprintf("<!-- connector-publish-action:%s@%s -->", connectorName, version)
}

// NewConnectorInput bundles everything a first-registration PR needs.
type NewConnectorInput struct {
	Name                    string
	DisplayName             string
	Description             string
	Repository              string
	ExpectedOIDCIssuer      string
	ExpectedIdentityPattern string
	Version                 conduitindex.ConnectorVersion
}

// BuildNewConnector assembles the full connector object a first-registration
// PR proposes (step4 §3.1): name, publisher identity pin, and exactly one
// connectorVersion.
func BuildNewConnector(in NewConnectorInput) conduitindex.Connector {
	return conduitindex.Connector{
		Name:        in.Name,
		DisplayName: in.DisplayName,
		Description: in.Description,
		Repository:  in.Repository,
		Publisher: conduitindex.Publisher{
			ExpectedOIDCIssuer:      in.ExpectedOIDCIssuer,
			ExpectedIdentityPattern: in.ExpectedIdentityPattern,
		},
		Versions: []conduitindex.ConnectorVersion{in.Version},
	}
}

// BuildVersionBump returns a copy of existing with newVersion appended to
// Versions — every other field (Name, DisplayName, Description,
// Repository, Publisher, and every prior Versions[] entry) is copied
// byte-for-field from the already-verified index entry, unchanged. This is
// the structural enforcement of step4 §3.2 step 3's scope-limited diff:
// this function has no parameter through which a caller could smuggle a
// Publisher/Name change into a version-bump.
func BuildVersionBump(existing conduitindex.Connector, newVersion conduitindex.ConnectorVersion) conduitindex.Connector {
	updated := existing
	updated.Versions = append(append([]conduitindex.ConnectorVersion{}, existing.Versions...), newVersion)
	return updated
}

// MarshalConnectorFile renders c as the index-repo per-connector source
// file this Action proposes (index/connectors/<name>.json in the
// ConduitIO/conduit-connector-registry topology — plan-v2 §8). This is
// UNSIGNED source content: only the index-repo's own signing job (root-key
// holder) ever produces the signed, canonicalized payload — this Action
// never signs anything here, per step4 §4's "verified is not a field this
// Action sets" contract.
func MarshalConnectorFile(c conduitindex.Connector) ([]byte, error) {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("prbuild: could not marshal connector entry: %w", err)
	}
	return append(b, '\n'), nil
}

// NewRegistrationPRBody is the fixed template for a first-registration PR
// (step4 §3.1) — the "root-of-trust decision, do not auto-merge" notice,
// plus the resolved-identity sanity-check line the reviewer checklist
// (plan-v2 §10) asks for.
func NewRegistrationPRBody(connectorName, resolvedSAN, builderID string, warnings []string, marker string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## New connector registration: `%s`\n\n", connectorName)
	b.WriteString("This PR registers a new connector name and pins the identity allowed to " +
		"publish it. **This is a root-of-trust decision — human review required, first-party " +
		"included. Do not auto-merge.**\n\n")
	fmt.Fprintf(&b, "**Resolved identity (this run's Fulcio cert SAN):** `%s`\n\n", resolvedSAN)
	fmt.Fprintf(&b, "**SLSA builder.id (expected, global constant):** `%s`\n\n", builderID)
	if len(warnings) > 0 {
		b.WriteString("**Warnings — resolve before merging:**\n\n")
		for _, w := range warnings {
			fmt.Fprintf(&b, "- %s\n", w)
		}
		b.WriteString("\n")
	}
	b.WriteString("Reviewer checklist (plan-v2 §10) — complete every item before approving:\n\n" +
		"- [ ] Out-of-band identity confirmation (org/repo is who it claims to be)\n" +
		"- [ ] Name-confusability check (Levenshtein distance <= 2 / lookalike substitution against every existing name)\n" +
		"- [ ] `resolved-identity` above matches the confirmed org/repo/workflow exactly, not a lookalike\n" +
		"- [ ] `expectedIdentityPattern` tightness: anchored, literal `github\\.com/<owner>/<repo>/` prefix, no inline RE2 flags, tag-scoped ref\n" +
		"- [ ] Runner-environment: if provenance is below L3 (self-hosted), confirm that is intentional\n\n" +
		"This PR label is `registry/new-registration` and must **never** carry `automerge`. If index-repo branch " +
		"protection ever adds an auto-merge bot, `registry/new-registration` must be on its exclusion list.\n\n")
	b.WriteString(marker + "\n")
	return b.String()
}

// VersionBumpPRBody is the fixed template for a version-bump PR (step4
// §3.2 step 4).
func VersionBumpPRBody(connectorName, version, resolvedSAN, builderID string, forcedHumanReview bool, marker string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Version bump: `%s` @ `%s`\n\n", connectorName, version)
	b.WriteString("This PR was opened by `connector-publish-action` after its own preflight confirmed the " +
		"resolved identity matches the pattern already pinned for this connector name. The diff below touches " +
		"only `connectors[].versions[]` for this name — no other field or connector is modified.\n\n")
	fmt.Fprintf(&b, "**Resolved identity:** `%s`\n\n", resolvedSAN)
	fmt.Fprintf(&b, "**SLSA builder.id (expected, global constant):** `%s`\n\n", builderID)
	if forcedHumanReview {
		b.WriteString("**This build ran on a self-hosted runner.** SLSA L3 provenance requires a GitHub-hosted, " +
			"ephemeral runner for its non-falsifiability guarantee — that does not hold here, so this PR is " +
			"forced to human review regardless of the identity match and does **not** carry `automerge`.\n\n")
	} else {
		b.WriteString("Labeled `automerge` — actual merge authority is the index repo's own branch-protection + " +
			"required-status-check configuration (index-CI re-verification), never invoked by this Action.\n\n")
	}
	b.WriteString(marker + "\n")
	return b.String()
}
