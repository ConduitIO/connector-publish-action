#!/usr/bin/env bash
# Copyright © 2026 Meroxa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# action.yml's mode=build step (step4-publishing-action.md §1.2 steps 1-5):
# for each (os, arch) in $BUILD_MATRIX, run $BUILD_COMMAND, compute
# sha256+size FROM THE FILE AS WRITTEN TO DISK (never re-derived from a
# later fetch — the load-bearing property that keeps a compromised/
# misbehaving download gateway from ever causing a successful
# wrong-artifact install, only a failed verification), cosign-sign it
# keylessly, upload both the artifact and its Sigstore bundle to the
# release for the triggering tag, and emit the `artifacts` +
# `provenance-subjects` outputs.
#
# Requires: jq, cosign (installed by action.yml's cosign-installer step
# before this runs — see the ordering note in action.yml), gh (preinstalled
# on GitHub-hosted runners), sha256sum or shasum.
#
# Ambient permissions required on the CALLING job: `id-token: write` (for
# cosign's keyless OIDC flow) and `contents: write` (for `gh release
# upload`) — documented in README.md and docs/reference-publish-workflow.yml.
set -euo pipefail

: "${BUILD_COMMAND:?BUILD_COMMAND is required in mode=build}"
: "${BUILD_MATRIX:?BUILD_MATRIX is required}"
: "${CONNECTOR_NAME:?CONNECTOR_NAME is required}"
: "${VERSION:?VERSION is required}"
: "${GITHUB_REPOSITORY:?}"
: "${GITHUB_REF_NAME:?}"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

WORKDIR="$(mktemp -d)"
ARTIFACTS_JSON="[]"

CELL_COUNT="$(echo "$BUILD_MATRIX" | jq 'length')"
if [ "$CELL_COUNT" -lt 1 ]; then
  echo "::error::build-matrix must contain at least one {os,arch} cell" >&2
  exit 1
fi

for i in $(seq 0 $((CELL_COUNT - 1))); do
  OS="$(echo "$BUILD_MATRIX" | jq -r ".[$i].os")"
  ARCH="$(echo "$BUILD_MATRIX" | jq -r ".[$i].arch")"
  OUT="$WORKDIR/${CONNECTOR_NAME}_${VERSION}_${OS}_${ARCH}"

  echo "::group::build ${OS}/${ARCH}"
  GOOS="$OS" GOARCH="$ARCH" OUTPUT_PATH="$OUT" bash -c "$BUILD_COMMAND"
  if [ ! -f "$OUT" ]; then
    echo "::error::build-command did not produce a file at \$OUTPUT_PATH ($OUT) for ${OS}/${ARCH}" >&2
    exit 1
  fi
  echo "::endgroup::"

  # Digest + size computed from the artifact exactly as written above —
  # never re-derived from a later fetch (step4 §1.2 step 2).
  DIGEST="$(sha256_of "$OUT")"
  SIZE="$(wc -c <"$OUT" | tr -d ' ')"

  BUNDLE="${OUT}.sigstore.json"
  echo "::group::cosign sign-blob ${OS}/${ARCH}"
  cosign sign-blob --yes \
    --oidc-issuer https://token.actions.githubusercontent.com \
    --bundle "$BUNDLE" \
    "$OUT"
  echo "::endgroup::"

  ASSET_NAME="$(basename "$OUT")"
  BUNDLE_NAME="$(basename "$BUNDLE")"
  gh release upload "$GITHUB_REF_NAME" "$OUT" "$BUNDLE" --repo "$GITHUB_REPOSITORY" --clobber

  ARTIFACT_URL="https://github.com/${GITHUB_REPOSITORY}/releases/download/${GITHUB_REF_NAME}/${ASSET_NAME}"
  BUNDLE_URL="https://github.com/${GITHUB_REPOSITORY}/releases/download/${GITHUB_REF_NAME}/${BUNDLE_NAME}"

  ARTIFACTS_JSON="$(echo "$ARTIFACTS_JSON" | jq \
    --arg os "$OS" --arg arch "$ARCH" --arg kind "standalone" \
    --arg url "$ARTIFACT_URL" --arg sha256 "$DIGEST" --argjson size "$SIZE" \
    --arg sigurl "$BUNDLE_URL" \
    '. + [{os:$os,arch:$arch,kind:$kind,url:$url,sha256:$sha256,size:$size,signatureBundleURL:$sigurl}]')"
done

PROVENANCE_SUBJECTS="$(echo "$ARTIFACTS_JSON" | jq -c '[.[] | {name: (.os + "-" + .arch), digest: {sha256: .sha256}}]' | base64 | tr -d '\n')"

{
  echo "artifacts<<REGISTRY_PR_EOF"
  echo "$ARTIFACTS_JSON"
  echo "REGISTRY_PR_EOF"
  echo "provenance-subjects<<REGISTRY_PR_EOF"
  echo "$PROVENANCE_SUBJECTS"
  echo "REGISTRY_PR_EOF"
} >>"$GITHUB_OUTPUT"

rm -rf "$WORKDIR"
