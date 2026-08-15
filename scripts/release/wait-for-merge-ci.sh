#!/usr/bin/env bash
set -euo pipefail

for attempt in $(seq 1 180); do
    read -r run_id status conclusion < <(
        gh api "repos/$GITHUB_REPOSITORY/actions/workflows/ci.yml/runs?head_sha=$SHA&event=push&per_page=1" \
            --jq '.workflow_runs[0] // empty | "\(.id) \(.status) \(.conclusion)"'
    ) || true
    if [[ -z "${run_id:-}" ]]; then
        echo "($attempt) waiting for CI to start on $SHA"
        sleep 20
        continue
    fi
    echo "($attempt) CI run $run_id is $status/$conclusion"
    if [[ "$status" == "completed" ]]; then
        if [[ "$conclusion" == "success" ]]; then
            echo "run_id=$run_id" >> "$GITHUB_OUTPUT"
            exit 0
        fi
        echo "::error::CI run $run_id concluded '$conclusion'; refusing to publish."
        exit 1
    fi
    sleep 20
done
echo "::error::Timed out waiting for CI on $SHA."
exit 1
