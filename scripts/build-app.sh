#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

swift build -c release --product Harbor

APP="dist/SSHTree.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp .build/release/Harbor "$APP/Contents/MacOS/Harbor"
cp App/Info.plist "$APP/Contents/Info.plist"
if [[ -f App/AppIcon.icns ]]; then
  cp App/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
fi
chmod +x "$APP/Contents/MacOS/Harbor"
codesign --force --sign - "$APP"
echo "Built $APP"
scripts/make-dmg.sh
