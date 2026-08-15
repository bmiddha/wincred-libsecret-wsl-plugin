#!/usr/bin/env bash
set -euo pipefail

if [[ "$CHANGE_SCOPE_RESULT" != "success" ]]; then
    echo "::error::Change-scope classification concluded '$CHANGE_SCOPE_RESULT'."
    exit 1
fi
if [[ "$REQUIRES_FULL_VALIDATION" != "true" ]]; then
    echo "CodeQL skipped because this pull request changes only documentation or repository metadata."
    exit 0
fi
case "$ANALYZE_RESULT" in
    success)
        echo "CodeQL analysis completed successfully."
        ;;
    skipped)
        echo "::notice title=CodeQL is not enabled::CodeQL runs automatically when this repository is public. Before publication, enable Code Security and set CODEQL_ENABLED to true on a supported plan."
        ;;
    *)
        echo "::error::CodeQL analysis concluded '$ANALYZE_RESULT'."
        exit 1
        ;;
esac
