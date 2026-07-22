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

// Package canary_test is the drift guard promised by
// docs/reference-publish-workflow.yml's `provenance` job comment.
//
// This repo's reference workflow pins slsa-github-generator's reusable
// workflow to a specific tag (the `provenance` job's `uses:` line). Quite
// separately, github.com/conduitio/conduit's pkg/registry/trust package
// pins the SAME tag as trust.ExpectedBuilderID — the ONLY predicate.builder.id
// value CheckProvenanceBinding accepts. The two constants live in different
// repositories and nothing in the type system links them: a future edit
// that bumps one without the other would either make every connector
// built from the reference workflow fail provenance verification (fails
// closed, but only discovered at verify time, potentially long after the
// reference workflow was copy-pasted into N connector repos) or, in the
// opposite and more dangerous direction, silently widen the trusted
// builder set if ExpectedBuilderID were the one that drifted.
//
// This test catches the mismatch at PR time in THIS repo, before either
// side ships, rather than relying solely on trust.CheckProvenanceBinding's
// fail-closed behavior at verify time in every downstream connector.
package canary_test

import (
	"os"
	"regexp"
	"testing"

	"github.com/conduitio/conduit/pkg/registry/trust"
)

// referenceWorkflowPath is relative to this package's directory, which is
// where `go test` sets the working directory.
const referenceWorkflowPath = "../../docs/reference-publish-workflow.yml"

// generatorUsesLine matches the `provenance` job's `uses:` line in
// docs/reference-publish-workflow.yml, e.g.:
//
//	uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0
//
// and captures the pinned ref (a short tag name, e.g. "v2.1.0" — the form
// `uses:` accepts, as opposed to the fully-qualified `refs/tags/v2.1.0`
// form the OIDC job_workflow_ref claim — and therefore builder.id —
// actually contains).
var generatorUsesLine = regexp.MustCompile(
	`(?m)^\s*uses:\s*slsa-framework/slsa-github-generator/\.github/workflows/generator_generic_slsa3\.yml@(\S+)\s*$`,
)

func TestGeneratorRefMatchesExpectedBuilderID(t *testing.T) {
	raw, err := os.ReadFile(referenceWorkflowPath)
	if err != nil {
		t.Fatalf("reading %s: %v", referenceWorkflowPath, err)
	}

	m := generatorUsesLine.FindSubmatch(raw)
	if m == nil {
		t.Fatalf(
			"%s: no `uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@<ref>` line found — "+
				"did the provenance job get renamed, restructured, or repointed at a different generator workflow file?",
			referenceWorkflowPath,
		)
	}
	pinnedTag := string(m[1])

	gotBuilderID := "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/" + pinnedTag

	if gotBuilderID != trust.ExpectedBuilderID {
		t.Fatalf(
			"%s pins the SLSA generator to tag %q, which resolves to builder.id\n\t%s\n"+
				"but github.com/conduitio/conduit's pkg/registry/trust.ExpectedBuilderID is\n\t%s\n"+
				"These MUST match — bump both together, in the same PR, with the same review rigor as an "+
				"identity change (a mismatch either breaks every connector's provenance verification or "+
				"silently widens the trusted builder set).",
			referenceWorkflowPath, pinnedTag, gotBuilderID, trust.ExpectedBuilderID,
		)
	}
}
