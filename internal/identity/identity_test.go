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

package identity_test

import (
	"strings"
	"testing"

	"github.com/ConduitIO/connector-publish-action/internal/identity"
)

func TestParseWorkflowRef(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		want    identity.Parts
		wantErr bool
	}{
		{
			name: "tag-triggered release workflow",
			ref:  "ConduitIO/conduit-connector-postgres/.github/workflows/publish.yml@refs/tags/v0.14.1",
			want: identity.Parts{
				Owner: "ConduitIO", Repo: "conduit-connector-postgres",
				WorkflowFile: ".github/workflows/publish.yml", Ref: "refs/tags/v0.14.1",
			},
		},
		{
			name: "branch push",
			ref:  "ConduitIO/conduit-connector-postgres/.github/workflows/publish.yml@refs/heads/main",
			want: identity.Parts{
				Owner: "ConduitIO", Repo: "conduit-connector-postgres",
				WorkflowFile: ".github/workflows/publish.yml", Ref: "refs/heads/main",
			},
		},
		{
			name:    "missing @ref",
			ref:     "ConduitIO/conduit-connector-postgres/.github/workflows/publish.yml",
			wantErr: true,
		},
		{
			name:    "empty ref suffix",
			ref:     "ConduitIO/conduit-connector-postgres/.github/workflows/publish.yml@",
			wantErr: true,
		},
		{
			name:    "no .github/workflows/ marker",
			ref:     "ConduitIO/conduit-connector-postgres/some/other/path.yml@refs/tags/v1",
			wantErr: true,
		},
		{
			name:    "no owner/repo separator",
			ref:     "justonesegment/.github/workflows/publish.yml@refs/tags/v1",
			wantErr: true,
		},
		{
			name: "nested workflow directory",
			ref:  "org/repo/.github/workflows/nested/publish.yml@refs/tags/v1.0.0",
			want: identity.Parts{
				Owner: "org", Repo: "repo",
				WorkflowFile: ".github/workflows/nested/publish.yml", Ref: "refs/tags/v1.0.0",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := identity.ParseWorkflowRef(tt.ref)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSAN(t *testing.T) {
	p := identity.Parts{
		Owner: "ConduitIO", Repo: "conduit-connector-postgres",
		WorkflowFile: ".github/workflows/publish.yml", Ref: "refs/tags/v0.14.1",
	}
	want := "https://github.com/ConduitIO/conduit-connector-postgres/.github/workflows/publish.yml@refs/tags/v0.14.1"
	if got := p.SAN(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestAssemblePattern(t *testing.T) {
	p := identity.Parts{
		Owner: "ConduitIO", Repo: "conduit-connector-postgres",
		WorkflowFile: ".github/workflows/publish.yml", Ref: "refs/tags/v0.14.1",
	}

	t.Run("tag-scoped ref pattern: no warnings, matches only the intended SAN", func(t *testing.T) {
		pattern, warnings, err := identity.AssemblePattern(p, `refs/tags/v[0-9]+\.[0-9]+\.[0-9]+`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(warnings) != 0 {
			t.Fatalf("expected no warnings, got %v", warnings)
		}
		match, err := identity.MatchesPinned(p.SAN(), pattern)
		if err != nil || !match {
			t.Fatalf("expected the assembled pattern to match its own SAN: match=%v err=%v", match, err)
		}
		// Must NOT match a different repo (the headline fork-attack shape:
		// same workflow file name, different owner/repo).
		forkSAN := "https://github.com/AttackerOrg/conduit-connector-postgres/.github/workflows/publish.yml@refs/tags/v0.14.1"
		match, err = identity.MatchesPinned(forkSAN, pattern)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if match {
			t.Fatalf("assembled pattern must not match a forked repo's SAN, but it did: %q", pattern)
		}
		// Must NOT match a branch ref if the human supplied a tag-only pattern.
		branchSAN := "https://github.com/ConduitIO/conduit-connector-postgres/.github/workflows/publish.yml@refs/heads/main"
		match, err = identity.MatchesPinned(branchSAN, pattern)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if match {
			t.Fatalf("tag-scoped pattern must not match a branch ref, but it did: %q", pattern)
		}
	})

	t.Run("branch-scoped ref pattern produces a warning, not an error", func(t *testing.T) {
		_, warnings, err := identity.AssemblePattern(p, `refs/heads/.*`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(warnings) == 0 {
			t.Fatalf("expected a branch-scoping warning, got none")
		}
		if !strings.Contains(warnings[0], "refs/tags/") {
			t.Fatalf("warning does not mention refs/tags/: %q", warnings[0])
		}
	})

	t.Run("empty ref pattern is rejected", func(t *testing.T) {
		_, _, err := identity.AssemblePattern(p, "")
		if err == nil {
			t.Fatal("expected an error for an empty ref pattern")
		}
	})

	t.Run("owner/repo/file segments are regex-escaped", func(t *testing.T) {
		dotted := identity.Parts{Owner: "Con.duit", Repo: "connector.postgres", WorkflowFile: ".github/workflows/publish.yml", Ref: "x"}
		pattern, _, err := identity.AssemblePattern(dotted, `refs/tags/v.*`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// A literal dot must not act as a regex wildcard: "Conxduit" must NOT match "Con.duit"'s pattern.
		wrongSAN := "https://github.com/Conxduit/connectorxpostgres/.github/workflows/publish.yml@refs/tags/v1"
		match, err := identity.MatchesPinned(wrongSAN, pattern)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if match {
			t.Fatalf("expected dots to be escaped (literal), but wildcard match succeeded: %q", pattern)
		}
	})
}
