#!/usr/bin/env bash
# Create a GitHub Release for every version in CHANGELOG.md that does not have one yet.
#   - tag vX.Y.Z on the commit "php2shell_check X.Y.Z"
#   - title "php2shell_check X.Y.Z", notes = that version's CHANGELOG section
#   - asset: php2shell_check.py exactly as it was in that commit
#   - the newest version is marked as latest
# Idempotent: existing releases are skipped. Needs: git, gh (logged in with `gh auth login`),
# a full (non-shallow) clone. Dry run without changes: DRY_RUN=1 bash tools/make-releases.sh
set -euo pipefail

REPO="${REPO:-rpersak/php2shell_check}"
DRY="${DRY_RUN:-0}"
cd "$(git rev-parse --show-toplevel)"

[ "$(git rev-parse --is-shallow-repository)" = "true" ] && git fetch --unshallow --quiet
git fetch --quiet origin main
if [ "$DRY" != "1" ]; then
  gh auth status >/dev/null 2>&1 || { echo "gh is not logged in: run 'gh auth login' first" >&2; exit 1; }
fi

mapfile -t VERSIONS < <(grep -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' CHANGELOG.md | tr -d '#[] ' )
[ "${#VERSIONS[@]}" -gt 0 ] || { echo "no versions found in CHANGELOG.md" >&2; exit 1; }
LATEST="${VERSIONS[0]}"            # CHANGELOG lists newest first
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# oldest first, so the release list is created in order
for (( i=${#VERSIONS[@]}-1; i>=0; i-- )); do
  v="${VERSIONS[$i]}"; tag="v$v"
  sha="$(git log origin/main --format=%H --grep="^php2shell_check ${v//./\\.}\$" -n1)"
  if [ -z "$sha" ]; then echo "skip $tag: no commit 'php2shell_check $v' found" >&2; continue; fi

  if [ "$DRY" != "1" ] && gh release view "$tag" --repo "$REPO" >/dev/null 2>&1; then
    echo "skip $tag: release already exists"; continue
  fi

  awk -v v="$v" '
    $0 ~ "^## \\[" v "\\]" {on=1; next}
    on && /^## \[/        {exit}
    on                    {print}
  ' CHANGELOG.md > "$WORK/notes-$v.md"
  printf '\nFull changelog: [CHANGELOG.md](https://github.com/%s/blob/main/CHANGELOG.md)\n' "$REPO" >> "$WORK/notes-$v.md"

  mkdir -p "$WORK/$v"
  git show "$sha:php2shell_check.py" > "$WORK/$v/php2shell_check.py"
  latest=false; [ "$v" = "$LATEST" ] && latest=true

  echo "$tag -> ${sha:0:7}  latest=$latest  notes=$(wc -l < "$WORK/notes-$v.md") lines  asset=$(wc -c < "$WORK/$v/php2shell_check.py") bytes"
  if [ "$DRY" = "1" ]; then
    sed 's/^/      | /' "$WORK/notes-$v.md" | head -6
    continue
  fi
  gh release create "$tag" "$WORK/$v/php2shell_check.py" \
    --repo "$REPO" --target "$sha" --title "php2shell_check $v" \
    --notes-file "$WORK/notes-$v.md" --latest="$latest"
done
echo "done"
