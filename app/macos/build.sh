#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
build_root="$repository_root/build/macos"
app_bundle="$build_root/RATtler.app"
portable=false
archive=false

for argument in "$@"; do
    case "$argument" in
        --portable) portable=true ;;
        --archive) archive=true ;;
        *) echo "unknown option: $argument" >&2; exit 2 ;;
    esac
done

if [[ -L "$build_root" ]]; then
    echo "refusing to use a symbolic-link build directory" >&2
    exit 2
fi
mkdir -p "$build_root"
find "$build_root" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
mkdir -p "$app_bundle/Contents/MacOS" "$app_bundle/Contents/Resources/Engine"

sdk_path=$(xcrun --sdk macosx --show-sdk-path)
architecture=$(uname -m)
xcrun --sdk macosx clang \
    -fobjc-arc -Wall -Wextra -Werror \
    -mmacosx-version-min=13.0 -isysroot "$sdk_path" \
    -framework AppKit -framework UniformTypeIdentifiers -framework WebKit \
    "$script_dir/Sources/main.m" \
    -o "$app_bundle/Contents/MacOS/RATtler"

cp "$script_dir/Info.plist" "$app_bundle/Contents/Info.plist"
cp -R "$script_dir/Resources/Web" "$app_bundle/Contents/Resources/Web"

if $portable; then
    python3 -m PyInstaller \
        --noconfirm --clean --onedir \
        --name rattler-engine \
        --paths "$repository_root/src" \
        --distpath "$build_root/engine-dist" \
        --workpath "$build_root/engine-work" \
        --specpath "$build_root" \
        "$script_dir/EngineEntry.py"
    cp -R "$build_root/engine-dist/rattler-engine/." "$app_bundle/Contents/Resources/Engine/"
else
    cp "$script_dir/DevelopmentEngine.sh" "$app_bundle/Contents/Resources/Engine/rattler-engine"
fi
chmod 755 "$app_bundle/Contents/MacOS/RATtler" "$app_bundle/Contents/Resources/Engine/rattler-engine"

icon_master="$build_root/RATtlerIcon-1024.png"
iconset="$build_root/RATtlerIcon.iconset"
xcrun --sdk macosx clang \
    -fobjc-arc -Wall -Wextra -Werror \
    -mmacosx-version-min=13.0 -isysroot "$sdk_path" \
    -framework AppKit "$script_dir/Tools/render_icon.m" \
    -o "$build_root/render-icon"
"$build_root/render-icon" "$icon_master"
mkdir -p "$iconset"
for specification in "16 icon_16x16.png" "32 icon_16x16@2x.png" \
    "32 icon_32x32.png" "64 icon_32x32@2x.png" \
    "128 icon_128x128.png" "256 icon_128x128@2x.png" \
    "256 icon_256x256.png" "512 icon_256x256@2x.png" \
    "512 icon_512x512.png" "1024 icon_512x512@2x.png"; do
    size=${specification%% *}
    filename=${specification#* }
    sips -z "$size" "$size" "$icon_master" --out "$iconset/$filename" >/dev/null
done
iconutil -c icns "$iconset" -o "$app_bundle/Contents/Resources/RATtlerIcon.icns"

codesign --force --deep --sign - "$app_bundle"

if $archive; then
    zip_artifact="$build_root/RATtler-0.7.0-macOS-$architecture.zip"
    checksum_artifact="$build_root/RATtler-0.7.0-macOS-$architecture.sha256"
    ditto -c -k --norsrc --noextattr --noqtn --noacl --keepParent "$app_bundle" "$zip_artifact"
    (
        cd "$build_root"
        shasum -a 256 "$(basename "$zip_artifact")" > "$checksum_artifact"
    )
    echo "$zip_artifact"
else
    echo "$app_bundle"
fi
