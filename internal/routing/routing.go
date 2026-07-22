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

// Package routing decides whether a publish run is a new-name registration
// or a version bump from an already-pinned identity, per
// conduit-registry-plans/step4-publishing-action.md §3. This is the
// highest-value package in this Action: every fork-attack defense this
// Action provides funnels through Decide, and Decide fails closed (returns
// Blocked, never silently falls back to NewName) on any ambiguity.
package routing

import (
	"fmt"

	conduitindex "github.com/conduitio/conduit/pkg/registry/index"

	"github.com/ConduitIO/connector-publish-action/internal/identity"
)

// Kind is the PR-routing outcome (step4-publishing-action.md §1.3's
// pr-kind output).
type Kind string

const (
	// KindNewName: connector-name is absent from the verified index.
	// Always human-reviewed, never automerge.
	KindNewName Kind = "new-name"
	// KindVersionBump: connector-name is present and this run's resolved
	// identity matches the pinned pattern. Labeled automerge UNLESS the
	// runner is self-hosted (ForceHumanReview).
	KindVersionBump Kind = "version-bump"
	// KindBlockedSelfHosted is never returned by Decide directly — see
	// Decision.ForceHumanReview instead. Kept here only so pr-kind's
	// documented enum (step4 §1.3) is representable end-to-end by whatever
	// serializes Decision to the action's output.
	KindBlockedSelfHosted Kind = "blocked-self-hosted"
	// KindBlockedIdentityMismatch: Decide returns this as an error, not a
	// successful Decision — see IdentityMismatchError. Listed here to
	// document the full pr-kind enum from step4 §1.3.
	KindBlockedIdentityMismatch Kind = "blocked-identity-mismatch"
)

const (
	LabelNewRegistration = "registry/new-registration"
	LabelVersionBump     = "registry/version-bump"
	LabelAutomerge       = "automerge"
	LabelHumanReview     = "registry/human-review-required"
)

// RunnerEnvironment mirrors the Fulcio certificate's runner-environment
// claim ("github-hosted" vs "self-hosted") — step4 §3.2 step 2 / §5's
// self-hosted row: a version built on a non-ephemeral runner does not earn
// the low-touch automerge path even from the correctly pinned identity,
// because L3's non-falsifiability assumption doesn't hold for self-hosted
// builds.
type RunnerEnvironment string

const (
	RunnerGitHubHosted RunnerEnvironment = "github-hosted"
	RunnerSelfHosted   RunnerEnvironment = "self-hosted"
)

// Decision is Decide's successful outcome.
type Decision struct {
	Kind Kind
	// ExistingConnector is set only for KindVersionBump — the connector
	// entry as it exists in the verified index right now, so the caller
	// can build a version-bump diff that touches ONLY versions[] (never
	// re-derives publisher/name/displayName/description/repository from
	// anything other than this already-verified value).
	ExistingConnector *conduitindex.Connector
	Labels            []string
	AutoMerge         bool
	ForceHumanReview  bool // self-hosted runner: labels above already reflect this; kept for the caller's own logging/summary.
}

// IdentityMismatchError is returned by Decide when connector-name IS
// present in the index but this run's resolved identity does NOT match
// its pinned publisher.expectedIdentityPattern (step4 §3.2 step 1's
// preflight). This is a courtesy fail-fast for legitimate maintainers
// (catches an org rename/workflow-path change in the connector repo's own
// CI logs) — it is NOT the security boundary (index-CI's independent
// re-verification is); see step4 §3.2 step 1's doc comment. Decide never
// falls back to KindNewName on this error — a name collision with a
// mismatched identity is never silently treated as "must be a fresh
// registration".
type IdentityMismatchError struct {
	ConnectorName string
	ResolvedSAN   string
	PinnedPattern string
}

func (e *IdentityMismatchError) Error() string {
	return fmt.Sprintf(
		"resolved identity %q does not match the pinned pattern for %q (%q). "+
			"If this is an intentional org move or workflow rename, open a human-reviewed re-pin PR — "+
			"this run will not publish.",
		e.ResolvedSAN, e.ConnectorName, e.PinnedPattern)
}

// Decide implements step4-publishing-action.md §3's routing table. verified
// MUST be the Verified flag from a real index.Verify call (never
// ParseUnverified) — Decide refuses via panic-free error rather than
// silently trusting an unverified index, mirroring pkg/registry's own
// Verified-bool belt-and-suspenders check (plan-v2 §2.2).
func Decide(payload *conduitindex.Payload, verified bool, connectorName, resolvedSAN string, runnerEnv RunnerEnvironment) (Decision, error) {
	if !verified {
		return Decision{}, fmt.Errorf("routing: refusing to route against an unverified index — Decide must only be called with a cryptographically verified index")
	}
	if payload == nil {
		return Decision{}, fmt.Errorf("routing: nil payload")
	}

	existing := findConnector(payload, connectorName)
	if existing == nil {
		return Decision{
			Kind:      KindNewName,
			Labels:    []string{LabelNewRegistration},
			AutoMerge: false,
		}, nil
	}

	match, err := identity.MatchesPinned(resolvedSAN, existing.Publisher.ExpectedIdentityPattern)
	if err != nil {
		return Decision{}, fmt.Errorf("routing: could not evaluate pinned pattern for %q: %w", connectorName, err)
	}
	if !match {
		return Decision{}, &IdentityMismatchError{
			ConnectorName: connectorName,
			ResolvedSAN:   resolvedSAN,
			PinnedPattern: existing.Publisher.ExpectedIdentityPattern,
		}
	}

	if runnerEnv == RunnerSelfHosted {
		return Decision{
			Kind:              KindVersionBump,
			ExistingConnector: existing,
			Labels:            []string{LabelVersionBump, LabelHumanReview},
			AutoMerge:         false,
			ForceHumanReview:  true,
		}, nil
	}

	return Decision{
		Kind:              KindVersionBump,
		ExistingConnector: existing,
		Labels:            []string{LabelVersionBump, LabelAutomerge},
		AutoMerge:         true,
	}, nil
}

func findConnector(payload *conduitindex.Payload, name string) *conduitindex.Connector {
	for i := range payload.Connectors {
		if payload.Connectors[i].Name == name {
			return &payload.Connectors[i]
		}
	}
	return nil
}
