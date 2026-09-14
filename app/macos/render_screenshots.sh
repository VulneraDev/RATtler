#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
build_directory="$repository_root/build/macos-screenshots"
renderer="$build_directory/render-screenshot"
web_page="$script_dir/Resources/Web/index.html"

mkdir -p "$build_directory" "$repository_root/docs/images"
sdk_path=$(xcrun --sdk macosx --show-sdk-path)
xcrun --sdk macosx clang \
    -fobjc-arc -Wall -Wextra -Werror \
    -mmacosx-version-min=13.0 -isysroot "$sdk_path" \
    -framework AppKit -framework WebKit \
    "$script_dir/Tools/render_screenshot.m" -o "$renderer"

"$renderer" "$web_page" "$repository_root/docs/fixtures/ui-healthy.json" \
    "$repository_root/docs/images/rattler-healthy.png"
"$renderer" "$web_page" "$repository_root/docs/fixtures/ui-risk.json" \
    "$repository_root/docs/images/rattler-risk.png"
"$renderer" "$web_page" "$repository_root/docs/fixtures/ui-healthy.json" \
    "$repository_root/docs/images/rattler-bluepulse.png" bluepulse

sips -z 760 1180 "$repository_root/docs/images/rattler-healthy.png" >/dev/null
sips -z 760 1180 "$repository_root/docs/images/rattler-risk.png" >/dev/null
sips -z 760 1180 "$repository_root/docs/images/rattler-bluepulse.png" >/dev/null
