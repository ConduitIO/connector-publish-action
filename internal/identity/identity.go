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

// Package identity computes the Fulcio certificate SAN a composite-action
// run resolves to, and assembles the fully-anchored
// publisher.expectedIdentityPattern regex a first registration pins.
//
// # Why this package must never guess
//
// The whole trust model (docs/design-documents/registry-index/index-schema.json,
// conduit-registry-plans/step4-publishing-action.md §0/§2) depends on the
// resolved SAN this package computes being EXACTLY what GitHub's Fulcio CA
// puts in the signing certificate's SAN for this job. That SAN is built
// from the OIDC token's job_workflow_ref claim, which — for a job that is
// NOT itself a reusable-workflow call (i.e. this Action, shipped as a
// composite action per step4-publishing-action.md §0) — is identical to
// the calling workflow's own github.workflow_ref context value:
// "<owner>/<repo>/<path-to-workflow>.yml@<ref>". See
// https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#understanding-the-oidc-token
// and GitHub's documented github.workflow_ref context field. This package
// takes that string as its only input — it never re-derives identity from
// github.repository/github.ref separately, because that would silently
// diverge from what Fulcio actually signs the moment this Action is ever
// invoked from a reusable workflow (which step4's §0 forbids for exactly
// this reason).
package identity

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/conduitio/conduit/pkg/registry/trust"
)

// Parts is the decomposition of a GitHub Actions workflow_ref string
// ("<owner>/<repo>/.github/workflows/<file>.yml@<ref>") into the pieces the
// resolved SAN and an assembled expectedIdentityPattern are both built
// from.
type Parts struct {
	Owner        string
	Repo         string
	WorkflowFile string // e.g. ".github/workflows/publish.yml"
	Ref          string // e.g. "refs/tags/v0.14.1"
}

// ParseWorkflowRef parses GitHub's github.workflow_ref context value. This
// value is ALWAYS of the shape "<owner>/<repo>/<workflow-path>@<ref>" —
// GitHub guarantees the workflow path is rooted at ".github/workflows/"
// for any workflow triggerable at all, so splitting on the first "@" and
// then locating ".github/workflows/" in the remainder is unambiguous.
func ParseWorkflowRef(workflowRef string) (Parts, error) {
	at := strings.LastIndex(workflowRef, "@")
	if at < 0 {
		return Parts{}, fmt.Errorf("identity: workflow ref %q has no @<ref> suffix", workflowRef)
	}
	path, ref := workflowRef[:at], workflowRef[at+1:]
	if ref == "" {
		return Parts{}, fmt.Errorf("identity: workflow ref %q has an empty ref", workflowRef)
	}

	const marker = "/.github/workflows/"
	idx := strings.Index(path, marker)
	if idx < 0 {
		return Parts{}, fmt.Errorf("identity: workflow ref %q does not contain %q", workflowRef, marker)
	}
	ownerRepo := path[:idx]
	workflowFile := path[idx+1:] // ".github/workflows/<file>.yml", drop the leading "/"

	slash := strings.Index(ownerRepo, "/")
	if slash < 0 {
		return Parts{}, fmt.Errorf("identity: workflow ref %q has no owner/repo separator before %q", workflowRef, marker)
	}
	owner, repo := ownerRepo[:slash], ownerRepo[slash+1:]
	if owner == "" || repo == "" || strings.Contains(repo, "/") {
		return Parts{}, fmt.Errorf("identity: workflow ref %q does not decompose into a single owner/repo pair", workflowRef)
	}

	return Parts{Owner: owner, Repo: repo, WorkflowFile: workflowFile, Ref: ref}, nil
}

// SAN reconstructs the exact Fulcio certificate-SAN string this run signs
// as: "https://github.com/<owner>/<repo>/<workflow-file>@<ref>". This is
// the "resolved-identity" output (step4-publishing-action.md §1.3).
func (p Parts) SAN() string {
	return fmt.Sprintf("https://github.com/%s/%s/%s@%s", p.Owner, p.Repo, p.WorkflowFile, p.Ref)
}

// AssemblePattern builds the fully-anchored expectedIdentityPattern for a
// FIRST REGISTRATION (step4-publishing-action.md §2): the owner/repo/
// workflow-file portion is mechanically derived from this run's own
// resolved SAN (facts about this run, not a trust decision); the ref
// portion is exactly refPattern, which the caller MUST have sourced from
// the human-supplied first-registration-identity-ref-pattern input, never
// from p.Ref itself — auto-deriving from "whatever ref triggered this run"
// would scope trust to whatever the current push happens to be (a branch,
// during setup) rather than what a maintainer actually intends to trust
// going forward. This function has no way to enforce that its caller
// respected that rule (it only sees the resulting string); cmd/registry-pr
// is responsible for never passing p.Ref here.
//
// The assembled pattern is validated with trust.ValidateIdentityPattern
// (the SAME tightness check pkg/registry/trust applies defensively at
// verify time and index-CI applies at lint time — plan-v2 §10) before
// being returned, so this Action can never hand a reviewer a pattern that
// would fail that check. A non-fatal warning is returned (not an error)
// when refPattern does not look tag-scoped, since scoping to tags vs.
// branches is a judgment call step4-publishing-action.md §5 assigns to
// human review, not to this Action refusing to run — but the run should
// make that judgment easy, not silent.
func AssemblePattern(p Parts, refPattern string) (pattern string, warnings []string, err error) {
	if refPattern == "" {
		return "", nil, fmt.Errorf("identity: first-registration ref pattern must not be empty")
	}

	escapedOwner := regexp.QuoteMeta(p.Owner)
	escapedRepo := regexp.QuoteMeta(p.Repo)
	escapedFile := regexp.QuoteMeta(p.WorkflowFile)

	pattern = fmt.Sprintf(`^https://github\.com/%s/%s/%s@%s$`, escapedOwner, escapedRepo, escapedFile, refPattern)

	if _, compileErr := regexp.Compile(pattern); compileErr != nil {
		return "", nil, fmt.Errorf("identity: assembled pattern %q does not compile as RE2: %w", pattern, compileErr)
	}
	if validateErr := trust.ValidateIdentityPattern(pattern); validateErr != nil {
		return "", nil, fmt.Errorf("identity: assembled pattern fails tightness validation: %w", validateErr)
	}

	if !strings.HasPrefix(refPattern, `refs/tags/`) {
		warnings = append(warnings, fmt.Sprintf(
			"ref pattern %q does not start with the literal \"refs/tags/\" — confirm this is deliberately "+
				"scoped to tags and not a branch ref before merging; a branch-scoped pattern lets any push to "+
				"that branch re-sign this connector name", refPattern))
	}

	return pattern, warnings, nil
}

// MatchesPinned reports whether resolvedSAN satisfies pinnedPattern
// (already-anchored, per trust.ValidateIdentityPattern). Uses Go's
// stdlib regexp (RE2) — the same engine sigstore-go's certificate-identity
// matcher compiles patterns with (pkg/registry/trust/sigstore.go's doc
// comment on certificateIdentityFor), so a match/no-match verdict here
// agrees with what trust.VerifySignedEntitySignature would decide.
func MatchesPinned(resolvedSAN, pinnedPattern string) (bool, error) {
	re, err := regexp.Compile(pinnedPattern)
	if err != nil {
		return false, fmt.Errorf("identity: pinned pattern %q does not compile as RE2: %w", pinnedPattern, err)
	}
	return re.MatchString(resolvedSAN), nil
}
