#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
if [[ ! -x "$DEVELOPER_DIR/usr/bin/xcodebuild" ]]; then
  echo "SSHTree requires full Xcode 27. Set DEVELOPER_DIR to its Contents/Developer directory." >&2
  exit 1
fi
xcodebuild -project SSHTree.xcodeproj -scheme SSHTree -skipPackagePluginValidation -configuration Release \
  -destination 'generic/platform=macOS' -derivedDataPath .build/Xcode \
  CODE_SIGN_IDENTITY=- build
mkdir -p dist
if [[ -e dist/SSHTree.app ]]; then rm -r dist/SSHTree.app; fi
ditto .build/Xcode/Build/Products/Release/SSHTree.app dist/SSHTree.app
codesign --verify --deep --strict dist/SSHTree.app
echo "Built $(pwd)/dist/SSHTree.app"
"$(dirname "$0")/make-dmg.sh"
