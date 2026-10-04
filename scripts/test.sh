#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
# Xcode's testmanager launches a separate runner. Keep its products outside
# Documents/Desktop so macOS does not need access to private user folders.
test_products="${SSHTREE_TEST_DERIVED_DATA:-$HOME/Library/Developer/Xcode/DerivedData/SSHTreeTests}"
xcodebuild -project SSHTree.xcodeproj -scheme SSHTree -skipPackagePluginValidation -configuration Debug \
  -destination 'platform=macOS' -derivedDataPath "$test_products" \
  CODE_SIGN_IDENTITY=- test
