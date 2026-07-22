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

// Command registry-pr is the composite action's "plan" step (action.yml
// step 6, step4-publishing-action.md §1.2): it resolves this run's
// identity, fetches+verifies the index, decides new-name vs. version-bump
// vs. refuses (routing.Decide), and writes the PR content + metadata a
// following bash step (action.yml) turns into an actual git commit + `gh
// pr create` call. This binary never calls git/gh itself and never has
// network write access to any repo — it only reads the index and writes
// local files, keeping the actual git/GitHub side-effecting operations in
// plainly-reviewable shell in action.yml rather than hidden inside a
// compiled binary.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	conduitindex "github.com/conduitio/conduit/pkg/registry/index"
	"github.com/conduitio/conduit/pkg/registry/trust"

	"github.com/ConduitIO/connector-publish-action/internal/identity"
	"github.com/ConduitIO/connector-publish-action/internal/indexfetch"
	"github.com/ConduitIO/connector-publish-action/internal/prbuild"
	"github.com/ConduitIO/connector-publish-action/internal/routing"
)

type artifactInput struct {
	OS                 string `json:"os"`
	Arch               string `json:"arch"`
	Kind               string `json:"kind"`
	URL                string `json:"url"`
	SHA256             string `json:"sha256"`
	Size               int64  `json:"size"`
	SignatureBundleURL string `json:"signatureBundleURL"`
}

type config struct {
	workflowRef         string
	connectorName       string
	version             string
	displayName         string
	description         string
	repository          string
	minConduitVersion   string
	minProtocolVersion  string
	buildMatrixJSON     string
	provenanceBundleURL string
	provenancePredicate string
	firstRegRefPattern  string
	indexRepo           string
	indexJSONURL        string
	trustAnchorsPath    string
	runnerEnvironment   string
	dryRun              bool
	outputDir           string
	githubOutputPath    string
}

// planResult is what this command writes to <outputDir>/pr-meta.json for
// action.yml's bash steps to consume with jq.
type planResult struct {
	PRKind             string   `json:"prKind"`
	Blocked            bool     `json:"blocked"`
	BlockReason        string   `json:"blockReason,omitempty"`
	ResolvedIdentity   string   `json:"resolvedIdentity"`
	BuilderID          string   `json:"builderId"`
	Labels             []string `json:"labels"`
	AutoMerge          bool     `json:"autoMerge"`
	Marker             string   `json:"marker"`
	ConnectorFilePath  string   `json:"connectorFilePath"`
	PRTitle            string   `json:"prTitle"`
	PRBody             string   `json:"prBody"`
	Warnings           []string `json:"warnings,omitempty"`
	ProvenanceSubjects string   `json:"provenanceSubjects"`
	DryRun             bool     `json:"dryRun"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "registry-pr: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := parseFlags(args)
	if err != nil {
		return err
	}

	parts, err := identity.ParseWorkflowRef(cfg.workflowRef)
	if err != nil {
		return err
	}
	resolvedSAN := parts.SAN()

	var artifacts []artifactInput
	if err := json.Unmarshal([]byte(cfg.buildMatrixJSON), &artifacts); err != nil {
		return fmt.Errorf("parsing --build-matrix-json: %w", err)
	}
	if len(artifacts) == 0 {
		return fmt.Errorf("--build-matrix-json produced zero artifacts")
	}

	provenanceSubjects, err := provenanceSubjectsBase64(artifacts)
	if err != nil {
		return err
	}

	indexArtifacts := make([]conduitindex.Artifact, 0, len(artifacts))
	for _, a := range artifacts {
		indexArtifacts = append(indexArtifacts, conduitindex.Artifact{
			OS:     a.OS,
			Arch:   a.Arch,
			Kind:   a.Kind,
			URL:    a.URL,
			SHA256: a.SHA256,
			Size:   a.Size,
			Signature: conduitindex.SignatureRef{
				BundleURL: a.SignatureBundleURL,
			},
		})
	}

	now := time.Now().UTC()
	newVersion := conduitindex.ConnectorVersion{
		Version:            cfg.version,
		ReleasedAt:         &now,
		MinConduitVersion:  cfg.minConduitVersion,
		MinProtocolVersion: cfg.minProtocolVersion,
		Artifacts:          indexArtifacts,
	}
	if cfg.provenanceBundleURL != "" {
		newVersion.SLSAProvenance = &conduitindex.ProvenanceRef{
			BundleURL:     cfg.provenanceBundleURL,
			PredicateType: cfg.provenancePredicate,
		}
	}

	result := planResult{
		ResolvedIdentity:   resolvedSAN,
		BuilderID:          trust.ExpectedBuilderID,
		ProvenanceSubjects: provenanceSubjects,
		DryRun:             cfg.dryRun,
		Marker:             prbuild.IdempotencyMarker(cfg.connectorName, cfg.version),
	}

	anchorsRaw, err := readOptionalFile(cfg.trustAnchorsPath)
	if err != nil {
		return err
	}
	anchors, err := indexfetch.LoadTrustAnchors(anchorsRaw)
	if err != nil {
		return err
	}

	ctx := context.Background()
	verified, err := indexfetch.FetchAndVerify(ctx, cfg.indexJSONURL, anchors, "")
	if err != nil {
		return fmt.Errorf("fetching/verifying index at %s: %w", cfg.indexJSONURL, err)
	}

	runnerEnv := routing.RunnerGitHubHosted
	if cfg.runnerEnvironment == string(routing.RunnerSelfHosted) {
		runnerEnv = routing.RunnerSelfHosted
	}

	decision, err := routing.Decide(&verified.Payload, verified.Verified, cfg.connectorName, resolvedSAN, runnerEnv)
	if err != nil {
		var mismatch *routing.IdentityMismatchError
		if isIdentityMismatch(err, &mismatch) {
			result.Blocked = true
			result.BlockReason = mismatch.Error()
			result.PRKind = "blocked-identity-mismatch"
			return writeResult(cfg, result, true)
		}
		return fmt.Errorf("routing decision: %w", err)
	}

	result.Labels = decision.Labels
	result.AutoMerge = decision.AutoMerge

	switch decision.Kind {
	case routing.KindNewName:
		if cfg.firstRegRefPattern == "" {
			return fmt.Errorf("connector %q is not yet registered: --first-registration-ref-pattern is required for a new-name registration", cfg.connectorName)
		}
		pattern, warnings, err := identity.AssemblePattern(parts, cfg.firstRegRefPattern)
		if err != nil {
			return fmt.Errorf("assembling expectedIdentityPattern: %w", err)
		}
		result.Warnings = warnings

		connector := prbuild.BuildNewConnector(prbuild.NewConnectorInput{
			Name:                    cfg.connectorName,
			DisplayName:             cfg.displayName,
			Description:             cfg.description,
			Repository:              cfg.repository,
			ExpectedOIDCIssuer:      "https://token.actions.githubusercontent.com",
			ExpectedIdentityPattern: pattern,
			Version:                 newVersion,
		})
		fileBytes, err := prbuild.MarshalConnectorFile(connector)
		if err != nil {
			return err
		}
		result.PRKind = "new-name"
		result.ConnectorFilePath = connectorFilePath(cfg.connectorName)
		result.PRTitle = fmt.Sprintf("registry: register %s @ %s", cfg.connectorName, cfg.version)
		result.PRBody = prbuild.NewRegistrationPRBody(cfg.connectorName, resolvedSAN, trust.ExpectedBuilderID, warnings, result.Marker)
		if err := writeConnectorFile(cfg, result.ConnectorFilePath, fileBytes); err != nil {
			return err
		}

	case routing.KindVersionBump:
		updated := prbuild.BuildVersionBump(*decision.ExistingConnector, newVersion)
		fileBytes, err := prbuild.MarshalConnectorFile(updated)
		if err != nil {
			return err
		}
		result.PRKind = "version-bump"
		result.ConnectorFilePath = connectorFilePath(cfg.connectorName)
		result.PRTitle = fmt.Sprintf("registry: %s %s", cfg.connectorName, cfg.version)
		result.PRBody = prbuild.VersionBumpPRBody(cfg.connectorName, cfg.version, resolvedSAN, trust.ExpectedBuilderID, decision.ForceHumanReview, result.Marker)
		if err := writeConnectorFile(cfg, result.ConnectorFilePath, fileBytes); err != nil {
			return err
		}

	default:
		return fmt.Errorf("unhandled routing decision kind %q", decision.Kind)
	}

	return writeResult(cfg, result, false)
}

func isIdentityMismatch(err error, target **routing.IdentityMismatchError) bool {
	m, ok := err.(*routing.IdentityMismatchError)
	if ok {
		*target = m
	}
	return ok
}

func connectorFilePath(name string) string {
	return fmt.Sprintf("index/connectors/%s.json", name)
}

func provenanceSubjectsBase64(artifacts []artifactInput) (string, error) {
	type subject struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	}
	subjects := make([]subject, 0, len(artifacts))
	for _, a := range artifacts {
		subjects = append(subjects, subject{
			Name:   fmt.Sprintf("%s-%s", a.OS, a.Arch),
			Digest: map[string]string{"sha256": a.SHA256},
		})
	}
	b, err := json.Marshal(subjects)
	if err != nil {
		return "", fmt.Errorf("marshaling provenance subjects: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func writeConnectorFile(cfg config, relPath string, content []byte) error {
	full := cfg.outputDir + "/" + relPath
	if err := os.MkdirAll(dirOf(full), 0o755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}
	if err := os.WriteFile(full, content, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", full, err)
	}
	return nil
}

func writeResult(cfg config, result planResult, blocked bool) error {
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	metaPath := cfg.outputDir + "/pr-meta.json"
	if err := os.MkdirAll(cfg.outputDir, 0o755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}
	if err := os.WriteFile(metaPath, b, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", metaPath, err)
	}

	if err := appendGitHubOutput(cfg.githubOutputPath, map[string]string{
		"resolved-identity":   result.ResolvedIdentity,
		"builder-id":          result.BuilderID,
		"pr-kind":             result.PRKind,
		"provenance-subjects": result.ProvenanceSubjects,
	}); err != nil {
		return err
	}

	if blocked {
		return fmt.Errorf("%s", result.BlockReason)
	}
	return nil
}

func appendGitHubOutput(path string, kv map[string]string) error {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("opening GITHUB_OUTPUT file: %w", err)
	}
	defer f.Close()
	for k, v := range kv {
		if _, err := fmt.Fprintf(f, "%s<<REGISTRY_PR_EOF\n%s\nREGISTRY_PR_EOF\n", k, v); err != nil {
			return fmt.Errorf("writing GITHUB_OUTPUT entry %q: %w", k, err)
		}
	}
	return nil
}

func readOptionalFile(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return b, nil
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

// parseFlags parses args into a config using a fresh FlagSet (rather than
// the package-level flag.CommandLine) so it can be called more than once —
// each real process invocation calls it exactly once via main, but this
// also lets tests exercise run() end-to-end multiple times in the same
// process without a "flag redefined" panic.
func parseFlags(args []string) (config, error) {
	var cfg config
	fs := flag.NewFlagSet("registry-pr", flag.ContinueOnError)
	fs.StringVar(&cfg.workflowRef, "workflow-ref", os.Getenv("GITHUB_WORKFLOW_REF"), "GitHub Actions github.workflow_ref context value")
	fs.StringVar(&cfg.connectorName, "connector-name", "", "registry connector name")
	fs.StringVar(&cfg.version, "version", "", "semver version being published")
	fs.StringVar(&cfg.displayName, "display-name", "", "display name (new registration only)")
	fs.StringVar(&cfg.description, "description", "", "description (new registration only)")
	fs.StringVar(&cfg.repository, "repository", "", "source repository URL (new registration only)")
	fs.StringVar(&cfg.minConduitVersion, "min-conduit-version", "", "minConduitVersion")
	fs.StringVar(&cfg.minProtocolVersion, "min-protocol-version", "", "minProtocolVersion")
	fs.StringVar(&cfg.buildMatrixJSON, "build-matrix-json", "", `JSON list of {os,arch,kind,url,sha256,size,signatureBundleURL}`)
	fs.StringVar(&cfg.provenanceBundleURL, "provenance-bundle-url", "", "SLSA provenance bundle URL (from the caller's slsa-github-generator job)")
	fs.StringVar(&cfg.provenancePredicate, "provenance-predicate-type", "https://slsa.dev/provenance/v1", "SLSA provenance predicateType")
	fs.StringVar(&cfg.firstRegRefPattern, "first-registration-ref-pattern", "", "human-supplied ref-pattern fragment (new registration only)")
	fs.StringVar(&cfg.indexRepo, "index-repo", "ConduitIO/conduit-connector-registry", "index repo (owner/repo)")
	fs.StringVar(&cfg.indexJSONURL, "index-json-url", "", "override for the signed index.json URL (default derived from --index-repo)")
	fs.StringVar(&cfg.trustAnchorsPath, "trust-anchors-json", "", "optional path to a trust-anchors JSON file (see internal/indexfetch)")
	fs.StringVar(&cfg.runnerEnvironment, "runner-environment", "github-hosted", `"github-hosted" or "self-hosted" (runner.environment)`)
	fs.BoolVar(&cfg.dryRun, "dry-run", false, "skip nothing in planning; caller skips the PR-open step")
	fs.StringVar(&cfg.outputDir, "output-dir", ".registry-pr", "directory to write pr-meta.json and the connector file into")
	fs.StringVar(&cfg.githubOutputPath, "github-output", os.Getenv("GITHUB_OUTPUT"), "path to $GITHUB_OUTPUT")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}

	if cfg.indexJSONURL == "" {
		cfg.indexJSONURL = fmt.Sprintf("https://raw.githubusercontent.com/%s/main/index/dist/index.json", cfg.indexRepo)
	}
	return cfg, nil
}
