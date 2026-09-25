#!/usr/bin/env bash
# Publishes site/ to GitHub Pages through the public ayrshirepixels/vulnverdict-site repository.
#
# The product repository is private and the Free plan has no Pages for private repositories, so the
# site is mirrored to a public repository that holds nothing but these files. This repository stays
# the source: edit site/ here, commit, then run this script. It needs `gh` signed in as the account.
#   ./site/publish.sh            mirror and push
#   ./site/publish.sh --dry-run  show what would change
set -euo pipefail
MIRROR="ayrshirepixels/vulnverdict-site"
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

gh repo clone "$MIRROR" "$work/mirror" -- -q
cd "$work/mirror"
# Replace the mirror's content wholesale, so files removed here are removed there too.
find . -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
cp -R "$here"/. .
rm -f publish.sh
find . -name '.DS_Store' -o -name '*~' | xargs -r rm -f
touch .nojekyll   # serve files as they are; no Jekyll processing of folders such as assets/

if [ "${1:-}" = "--dry-run" ]; then git status --short; exit 0; fi
if [ -z "$(git status --porcelain)" ]; then echo "site is up to date"; exit 0; fi
git add -A
src="$(git -C "$here/.." rev-parse --short HEAD 2>/dev/null || echo unknown)"
git -c user.name="Ayrshire Pixels" -c user.email="chris@pless.uk" commit -q -m "Site as of VulnVerdict $src"
git push -q origin HEAD
echo "published: https://ayrshirepixels.github.io/vulnverdict-site/"
