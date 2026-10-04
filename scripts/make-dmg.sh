#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

APP="dist/SSHTree.app"
OUT="dist/SSHTree.dmg"
VOL="SSHTree"

if [[ ! -d "$APP" ]]; then
  echo "没有找到 $APP。先运行 scripts/build-app.sh" >&2
  exit 1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/sshtree-dmg.XXXXXX")"
MOUNT="/Volumes/$VOL"

detach() {
  if mount | grep -F " on $MOUNT " >/dev/null || mount | grep -F " on /private$MOUNT " >/dev/null; then
    hdiutil detach "$MOUNT" -quiet || hdiutil detach "$MOUNT" -force -quiet || diskutil unmount force "$MOUNT" || true
  fi
}
cleanup() {
  detach
  rm -rf "$WORK"
}
trap cleanup EXIT

if [[ -d "$MOUNT" ]]; then
  echo "安装卷 $MOUNT 已经存在。先推出它，再重新打包。" >&2
  exit 1
fi

swift scripts/dmg-background.swift "$WORK/background.png"

SIZE_MB="$(du -sm "$APP" | awk '{print $1 + 16}')"
hdiutil create -size "${SIZE_MB}m" -fs HFS+ -volname "$VOL" "$WORK/rw.dmg" >/dev/null
hdiutil attach "$WORK/rw.dmg" -readwrite -noverify -noautoopen -mountpoint "$MOUNT" >/dev/null

ditto "$APP" "$MOUNT/SSHTree.app"
ln -s /Applications "$MOUNT/Applications"
mkdir -p "$MOUNT/.background"
cp "$WORK/background.png" "$MOUNT/.background/background.png"
chflags hidden "$MOUNT/.background"
if [[ -f App/AppIcon.icns ]]; then
  cp App/AppIcon.icns "$MOUNT/.VolumeIcon.icns"
  xattr -wx com.apple.FinderInfo "0000000000000000040000000000000000000000000000000000000000000000" "$MOUNT" || true
fi

# Finder writes the icon positions into .DS_Store. A missing permission only skips the layout.
osascript <<APPLESCRIPT || echo "窗口布局未写入，镜像里仍可拖拽安装。" >&2
tell application "Finder"
  tell disk "$VOL"
    open
    set current view of container window to icon view
    set toolbar visible of container window to false
    set statusbar visible of container window to false
    set the bounds of container window to {120, 80, 760, 480}
    set viewOptions to the icon view options of container window
    set arrangement of viewOptions to not arranged
    set icon size of viewOptions to 112
    set background picture of viewOptions to file ".background:background.png"
    set position of item "SSHTree.app" of container window to {128, 148}
    set position of item "Applications" of container window to {400, 148}
    update without registering applications
    delay 1
    close
  end tell
end tell
APPLESCRIPT

sync
detach
rm -f "$OUT"
hdiutil convert "$WORK/rw.dmg" -format UDZO -imagekey zlib-level=9 -o "$OUT" >/dev/null
echo "Built $OUT"
