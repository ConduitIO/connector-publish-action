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

# action.yml's final step: turns the plan step's already-computed,
# already-scope-checked PR content (.registry-pr/pr-meta.json +
# .registry-pr/index/connectors/<name>.json) into an actual git commit +
# `gh pr create`/update against $INDEX_REPO. Deliberately kept in plain,
# reviewable shell rather than inside the compiled registry-pr binary —
# the binary only ever reads the index and writes local files; every
# network-write / git-mutating operation against index-repo lives here,
# in one place, easy to audit.
#
# This script NEVER sets the automerge label's actual merge authority —
# it applies the label the plan step decided on, but merging is entirely
# index-repo's own branch-protection + required-status-check
# configuration (step4 §3.2 step 4). This script also never calls `gh pr
# merge` under any condition.
set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN (index-repo-token) is required to open a PR}"
: "${INDEX_REPO:?}"
: "${OUTPUT_DIR:?}"

META="$OUTPUT_DIR/pr-meta.json"
if [ ! -f "$META" ]; then
  echo "::error::$META not found — the plan step must run before this one" >&2
  exit 1
fi

BLOCKED="$(jq -r '.blocked' "$META")"
if [ "$BLOCKED" = "true" ]; then
  # Should be unreachable: the plan step already exits non-zero when
  # blocked, which stops the job before this step runs. Refuse anyway
  # rather than ever open a PR for a blocked run.
  echo "::error::plan step reported blocked=true — refusing to open a PR" >&2
  exit 1
fi

PR_KIND="$(jq -r '.prKind' "$META")"
CONNECTOR_FILE="$(jq -r '.connectorFilePath' "$META")"
PR_TITLE="$(jq -r '.prTitle' "$META")"
MARKER="$(jq -r '.marker' "$META")"
AUTOMERGE="$(jq -r '.autoMerge' "$META")"
mapfile -t LABELS < <(jq -r '.labels[]' "$META")

PR_BODY_FILE="$(mktemp)"
jq -r '.prBody' "$META" >"$PR_BODY_FILE"

if [ "$PR_KIND" = "new-name" ]; then
  echo "::notice::new-name registration for a root-of-trust decision — this PR will NOT be automerge-labeled regardless of the 'automerge' variable above" >&2
fi

CLONE_DIR="$(mktemp -d)"
git clone --depth 1 "https://x-access-token:${GH_TOKEN}@github.com/${INDEX_REPO}.git" "$CLONE_DIR"
cd "$CLONE_DIR"
git config user.name "connector-publish-action"
git config user.email "actions@users.noreply.github.com"

BRANCH="connector-publish-action/$(echo "$CONNECTOR_FILE" | sed -E 's#index/connectors/(.*)\.json#\1#')-$(jq -r '.resolvedIdentity' "$META" | md5sum | cut -c1-8)"

EXISTING_PR_NUMBER="$(gh pr list --repo "$INDEX_REPO" --state open --search "$MARKER in:body" --json number --jq '.[0].number // empty')"

if [ -n "$EXISTING_PR_NUMBER" ]; then
  echo "::notice::found existing open PR #$EXISTING_PR_NUMBER carrying this run's idempotency marker — updating it in place" >&2
  EXISTING_BRANCH="$(gh pr view "$EXISTING_PR_NUMBER" --repo "$INDEX_REPO" --json headRefName --jq '.headRefName')"
  git fetch origin "$EXISTING_BRANCH"
  git checkout "$EXISTING_BRANCH"
  BRANCH="$EXISTING_BRANCH"
else
  git checkout -b "$BRANCH"
fi

mkdir -p "$(dirname "$CONNECTOR_FILE")"
cp "$OUTPUT_DIR/$CONNECTOR_FILE" "$CONNECTOR_FILE"
git add "$CONNECTOR_FILE"

if git diff --cached --quiet; then
  echo "::notice::no changes to commit (this connector file is already up to date)" >&2
else
  git commit -m "$PR_TITLE"
  git push origin "$BRANCH"
fi

if [ -n "$EXISTING_PR_NUMBER" ]; then
  PR_URL="$(gh pr view "$EXISTING_PR_NUMBER" --repo "$INDEX_REPO" --json url --jq '.url')"
else
  LABEL_ARGS=()
  for l in "${LABELS[@]}"; do
    LABEL_ARGS+=(--label "$l")
  done
  PR_URL="$(gh pr create --repo "$INDEX_REPO" --title "$PR_TITLE" --body-file "$PR_BODY_FILE" --head "$BRANCH" "${LABEL_ARGS[@]}")"
fi

echo "pr-url=$PR_URL" >>"$GITHUB_OUTPUT"
echo "::notice::index PR: $PR_URL (kind=$PR_KIND autoMerge=$AUTOMERGE)" >&2
