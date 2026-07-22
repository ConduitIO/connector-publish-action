# connector-publish-action

Reusable GitHub Action: build, keyless-sign (cosign) and SLSA-L3-attest a Conduit connector, then
open a registry index PR.

> **Status: Tier-1 (supply-chain), not yet merged.** This repository implements PR-3 of the
> Conduit connector-registry MVP against `conduit-registry-plans/step4-publishing-action.md` and
> `registry-plan-v2.md`. It needs adversarial review and DeVaris's explicit sign-off before it
> merges — see the PR description for the failure-mode analysis. A compromised version of this
> Action compromises every future signed artifact in the registry; treat changes to `action.yml`
> and `internal/routing` with the highest bar in this org.

## What this Action does

A connector repo's release workflow calls this Action twice (see
[`docs/reference-publish-workflow.yml`](docs/reference-publish-workflow.yml) for the full,
copy-pasteable setup):

1. **`mode: build`** — build one artifact per `(os, arch)`, compute its digest from the bytes as
   written to disk, `cosign sign-blob` it keylessly (GitHub OIDC, no private key anywhere), upload
   the artifact + Sigstore bundle to the GitHub Release, and emit `provenance-subjects` for a
   separate SLSA provenance job to consume.
2. **`mode: publish`** (a later job, after SLSA provenance has been generated) — resolve this run's
   identity, fetch and cryptographically verify the current registry index (the *same*
   `pkg/registry/index.Verify` code `conduit connectors install` runs — no divergent logic), decide
   whether this is a new-name registration or a version bump, and open/update a PR against
   `ConduitIO/conduit-connector-registry`.

This is **not** a one-line adopt: it is a composite action plus a required, templated second job
for SLSA provenance. See the reference workflow for the full three-job shape.

## Why composite, not reusable — the load-bearing constraint

**This repository ships `action.yml` as a composite action, invoked via `uses:` steps *inside* the
calling connector repo's own job — never as a `workflow_call` reusable workflow.** Getting this
backwards silently destroys the entire trust model the registry depends on.

GitHub's OIDC token for a workflow run carries a `job_workflow_ref` claim, and that claim is what
becomes the Fulcio-issued certificate's SAN — the value `cosign verify --certificate-identity-regexp`
matches against, and the value the index's `publisher.expectedIdentityPattern` pins per connector
name.

- When a **job** is defined as `jobs.<id>.uses: org/repo/.github/workflows/x.yml@ref` (a reusable
  workflow), `job_workflow_ref` — and therefore the cert's SAN — resolves to **the reusable
  workflow's own repo and ref**, not the caller's.
- If this Action were shipped as a reusable workflow, *every* connector repo that called it would
  sign with the **identical** identity
  (`ConduitIO/connector-publish-action/.github/workflows/publish.yml@vX`). Per-connector-name
  identity pinning would have nothing real to pin against: `conduit-connector-postgres`'s
  legitimate publish and an attacker's forked-repo publish would be cryptographically
  indistinguishable — "anyone who can call the shared workflow is verified."
- A **composite action** (steps run inside the caller's own job — no `uses: .../workflows/*.yml@ref`
  job boundary) does not touch `job_workflow_ref`: it stays the calling repo's own workflow file +
  ref, e.g. `ConduitIO/conduit-connector-postgres/.github/workflows/publish.yml@refs/tags/v0.14.1`.
  That is exactly the shape `publisher.expectedIdentityPattern` in the frozen index schema encodes.

`.github/workflows/canary.yml` in this repo enforces this structurally, not just as a design note:
it decodes the real OIDC `job_workflow_ref` claim for a composite-shaped job and a genuine
reusable-workflow-call job and asserts the two resolved SANs differ (see "Composite-vs-reusable
canary" below) — a regression back to a reusable workflow fails this repo's own CI.

## Why SLSA provenance needs the opposite

Cosign identity-pinning wants the signing identity to be **exactly the calling repo** (above).
SLSA Build L3 wants the opposite: the provenance-*generating* process must be **isolated** from
the build process, so a compromised build job cannot forge its own provenance. That isolation is
exactly what `slsa-framework/slsa-github-generator`'s *reusable workflow* provides — it
deliberately runs as a separate job with its own identity, which becomes `predicate.builder.id` in
the emitted attestation.

These are two different identities checking two different things, and that's intentional:

| | Identity | Answers |
|---|---|---|
| cosign SAN (this Action, composite) | the calling connector repo's own workflow | "is this repo/workflow authorized to publish under this connector name?" |
| SLSA `builder.id` (slsa-github-generator, reusable) | the generator's own pinned reusable-workflow ref | "was this genuinely built by a non-forgeable, ephemeral, GitHub-hosted process?" |

`pkg/registry/trust.ExpectedBuilderID` in `github.com/conduitio/conduit` (shipped in PR-2) is the
single global constant every connector's provenance is checked against:

```text
https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0
```

This Action's `builder-id` output is this exact string — `internal/identity`/`cmd/registry-pr` read
it directly from the pinned `github.com/conduitio/conduit` dependency rather than hard-coding a
second copy, so the two can never silently drift apart. `docs/reference-publish-workflow.yml`
pins the generator to the matching tag (`v2.1.0`).

## New-name registration vs. version bump

`cmd/registry-pr` (`internal/routing.Decide`) implements the routing table from
`step4-publishing-action.md` §3:

| | New-name registration | Version bump |
|---|---|---|
| Trigger | `connector-name` absent from the verified index | `connector-name` present |
| Content | Full connector object incl. `publisher.expectedOIDCIssuer`/`expectedIdentityPattern` | Only `connectors[].versions[]` for this name — `internal/prbuild.BuildVersionBump` has no parameter through which a caller could smuggle a `publisher`/`name` change in |
| Preflight | `first-registration-identity-ref-pattern` must be human-supplied (never derived from the current ref alone) | This run's resolved identity is regex-matched against the *already-pinned* pattern; a mismatch fails the connector repo's **own CI run**, before any index PR exists |
| Labels | `registry/new-registration` | `registry/version-bump` + `automerge` (or `registry/human-review-required` instead of `automerge` on a self-hosted runner) |
| Merge authority | Human, always. This Action never sets an automerge label or calls `gh pr merge` for this kind. | Still never merged by this Action — `automerge` only requests index-repo's own branch-protection + required-status-check bot to do it, gated by index-CI's independent re-verification (a separate repo/plan) |

A version-bump PR can **never** register a new name or repoint an existing name's identity —
structurally, not just by convention: `BuildVersionBump`'s only inputs are the already-verified
existing connector and the new version, and there is no code path from a version-bump `Decision`
back into `BuildNewConnector`.

## The fork attack, and how it's refused at every layer

Attacker forks the reference workflow into `evil-org/conduit-connector-postgres-totally-legit`,
tags a release, and tries to publish under the existing name `postgres`.

1. **This Action's own preflight** (`internal/routing.Decide`, run inside the *attacker's own* CI):
   the resolved SAN is `.../evil-org/conduit-connector-postgres-totally-legit/...`, which does not
   match `postgres`'s pinned `expectedIdentityPattern`
   (`.../ConduitIO/conduit-connector-postgres/...`). `Decide` returns `IdentityMismatchError`; the
   run fails before any index PR is opened. See `internal/routing/routing_test.go`'s
   `TestDecide_ForkAttack` and `cmd/registry-pr/main_test.go`'s `TestRun_ForkAttack_IsRefused`.
2. **Even if the attacker hand-crafts an index PR bypassing this Action entirely**, index-CI's
   independent `cosign verify --certificate-identity-regexp <pinned pattern>` re-verification (a
   separate repo/plan; this Action does not own or depend on it) rejects it before merge.
3. **Even in the worst case where such a PR were merged by mistake**, a fresh
   `conduit connectors install postgres` re-verifies against the pinned identity via
   `pkg/registry/trust.VerifySignedEntitySignature` and refuses with `ErrIdentityMismatch` — proven
   against the REAL, unmodified verification code (not a mock) in
   `test/trustcore/e2e_test.go`'s `TestE2E_LegitimatePublisherVerifies_ForkIsRefused`: a
   cryptographically valid, validly Rekor-logged signature from the fork's own identity is
   refused, and specifically classified as `ErrIdentityMismatch` (not `ErrUnsigned` — the
   signature is real, just not by the pinned identity).

Three independent layers, and critically: a version-bump automerge path can never register a new
name or repoint an existing one's identity (above), so there is no route by which this attack
reaches automerge even if it somehow reached the index-PR stage at all.

## Composite-vs-reusable canary

`.github/workflows/canary.yml` (this repo's own CI, not a connector repo's) runs two jobs in a
single workflow run: `as_composite_caller`, a normal job standing in for the shape a composite
action's steps inherit, and `as_reusable_workflow_call`, a job defined via
`uses: ./.github/workflows/_reusable-echo-identity.yml` standing in for the misuse this Action must
never ship as. Both jobs fetch a real OIDC id-token (`actions/github-script` +
`core.getIDToken()`) and decode its `job_workflow_ref` claim directly — the actual value that
becomes the Fulcio certificate's SAN, **not** the `github.workflow_ref` context variable (which
always reflects the run's top-level entry workflow regardless of any nested `workflow_call`
boundary, so it can't distinguish the two shapes at all). A third job asserts the two decoded
identities differ and each names the right workflow file — the concrete, permanent regression test
against ever shipping this Action as a reusable workflow by accident (see
`step4-publishing-action.md` §5's "reusable-workflow misconfiguration" row).

**Honest scope note:** both jobs live in this one repository, so this proves the underlying
`job_workflow_ref` mechanism itself (repo-independent, and the root cause the whole
composite-vs-reusable design decision rests on) — it is not yet a true cross-repository canary
with two disposable connector-repo-shaped fixtures each `uses:`-ing this Action from a different
repo. That remains a follow-up, not silently substituted for.

## Known limitations (read before relying on this in production)

- **Root/freshness trust-anchor bootstrap is not complete.** `pkg/registry/index/anchors.go` in
  `github.com/conduitio/conduit` states plainly: *"No key material exists yet: it is generated
  during the bootstrap ceremony (plan-v2 §9)."* Until that ceremony ships real embedded anchors,
  this Action's `mode: publish` index-verify step (`internal/indexfetch.FetchAndVerify`) fails
  closed (`CodeTrustAnchorExpired`) against the zero-value default — this is **correct** fail-closed
  behavior, not a bug, but it means `mode: publish` cannot succeed against a real index today.
  `-trust-anchors-json` lets an operator (or index-CI, once it exists) supply real anchors once
  the ceremony completes, with no code change required here.
- **No persisted high-water mark across runs.** Unlike `conduit connectors install`, this Action
  is stateless (a fresh checkout every run) — `internal/indexfetch.FetchAndVerify` always passes
  an empty `lastVerifiedConnectorsHash`, so per `index.Verify`'s own contract it can only accept an
  index whose *latest* signature is root-signed, never a freshness-only heartbeat re-sign. If the
  index repo's automation ever needs this Action to route against a freshness-only-signed index,
  that requires passing a real previous hash in, not a change to this repo's verification logic.
- **`action.yml`'s `mode: publish` step still builds `registry-pr` from source at call time** (via
  `actions/setup-go`) rather than downloading the pre-built binary that `.github/workflows/release.yml`
  already attaches to tagged releases per OS/arch. `github.com/conduitio/conduit` is a public module
  (no `GOPRIVATE`/token needed to build this repo — see `go.mod`, pinned to a real commit on
  `ConduitIO/conduit`'s `main`), so building from source works today; wiring the pre-built-binary
  download in is still a follow-up, not done in this PR.
- **`index/connectors/<name>.json` is this Action's assumption about the index repo's per-connector
  source-file convention**, not a confirmed one — the index repo itself (plan-v2 §8) doesn't exist
  yet. If the real index repo uses a different layout, only `cmd/registry-pr`'s
  `connectorFilePath` function needs to change.

## Repository layout

```text
action.yml                        composite action definition
scripts/build-and-sign.sh         mode=build: matrix build, digest, cosign sign-blob, release upload
scripts/open-index-pr.sh          mode=publish: git commit + gh pr create/update against index-repo
cmd/registry-pr/                  the Go "plan" step: identity, index verify, routing, PR content
internal/identity/                workflow_ref parsing, resolved-SAN, expectedIdentityPattern assembly
internal/routing/                 new-name vs. version-bump vs. refuse (the fork-attack defense)
internal/prbuild/                 scope-limited PR content + body assembly
internal/indexfetch/              bounded fetch + pkg/registry/index.Verify wrapper
test/trustcore/                   E2E: this Action's output verifies against conduit's real trust core
docs/reference-publish-workflow.yml   copy-paste starting point for a connector repo
```

## Testing

```console
$ go test ./... -race
```

- `internal/identity`: workflow-ref parsing, SAN reconstruction, pattern assembly (anchoring,
  escaping, tag-vs-branch-scoping warning), fork-shaped non-matches.
- `internal/routing`: the full routing table, including `TestDecide_ForkAttack` and the
  self-hosted-forces-human-review case.
- `internal/prbuild`: structural proof that a version bump cannot widen its own diff.
- `cmd/registry-pr`: black-box integration tests against a real ed25519-signed index served over
  `httptest`, driving the actual CLI end-to-end for new-name, version-bump, fork-attack, and
  self-hosted-runner scenarios.
- `test/trustcore`: the north-star test — signs and attests fixtures with sigstore-go's official
  offline test harness (`ca.VirtualSigstore`, the same one `pkg/registry/trust/adversarial` uses),
  and verifies them against conduit's real, unmodified `pkg/registry/trust` functions.
