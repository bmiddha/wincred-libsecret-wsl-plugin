#!/usr/bin/env bash
set -euo pipefail

branch="release/$TAG"
if gh pr list --head "$branch" --state open --json url --jq '.[0].url // empty' | grep -q .; then
    echo "::error::An open release pull request already exists for '$TAG'."
    exit 1
fi
if git ls-remote --exit-code --heads origin "refs/heads/$branch" >/dev/null; then
    echo "::error::Release branch '$branch' already exists. Close and delete the stale branch before retrying."
    exit 1
fi

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git switch --create "$branch"
git add Cargo.toml Cargo.lock CHANGELOG.md
if git diff --cached --quiet; then
    echo "::error::Release preparation did not change its expected release files."
    exit 1
fi
git commit -m "chore(release): $TAG"
git push origin "$branch"

gh label create release --color 0e8a16 --description "Release preparation pull request" 2>/dev/null || true
labels=(--label release)
if [[ "$INITIAL_RELEASE" == "true" ]]; then
    gh label create initial-release --color 1d76db --description "Initial release bootstrap" 2>/dev/null || true
    labels+=(--label initial-release)
fi
if [[ "${PRERELEASE:-false}" == "true" ]]; then
    gh label create prerelease --color fbca04 --description "Prerelease publication" 2>/dev/null || true
    labels+=(--label prerelease)
fi
cat > release-pr.md <<EOF
Automated release preparation for **$TAG**.

Merge this pull request only after reviewing the version bump and its
normal CI results. The publish workflow will then wait for the merge
commit's CI run, run the hosted WSL end-to-end suite, sign the release
from those CI build inputs, create the tag, and publish the GitHub Release.

---

$(cat "$RUNNER_TEMP/release-notes.md")
EOF
gh pr create \
    --base "$BASE_BRANCH" \
    --head "$branch" \
    --title "chore(release): $TAG" \
    --body-file release-pr.md \
    "${labels[@]}"
