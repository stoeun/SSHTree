#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -d dist/SSHTree.app ]] || { echo "Run scripts/build-app.sh first." >&2; exit 1; }
mkdir -p release .build/dmg
stage="$(mktemp -d .build/dmg/stage.XXXXXX)"
trap 'rm -r "$stage"' EXIT
ditto dist/SSHTree.app "$stage/SSHTree.app"
ln -s /Applications "$stage/Applications"
cp LICENSE "$stage/LICENSE.txt"
hdiutil create -volname SSHTree -srcfolder "$stage" -format UDZO -ov release/SSHTree.dmg
hdiutil verify release/SSHTree.dmg
shasum -a 256 release/SSHTree.dmg > release/SHA256SUMS
echo "Created $(pwd)/release/SSHTree.dmg"
