#!/usr/bin/env bash
# check-theme.sh - every colour, font size and spacing value in the GUI
# comes from crates/candor-gui/src/theme.rs (redesign spec section 2.3).
# Fails if a colour constructor, a numeric font size or a numeric spacing
# value appears in any other GUI source file. Run by `make lint`.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
dir=crates/candor-gui/src
files=$(ls "$dir"/*.rs | grep -v '/theme.rs$')
pat='from_rgb|from_rgba|from_gray|Color32::[A-Z]{3,}|\.size\([0-9]|FontId::(new|proportional|monospace)\([0-9]|add_space\([0-9]|Margin::(same|symmetric)\([0-9]|vec2\([0-9.]*[1-9]|Stroke::new\([0-9]|CornerRadius::same\([0-9]|(space|size|radius)::[A-Z_]+ *[-+*/] *[0-9]|[-+*/] *(space|size|radius)::[A-Z_]+ *[-+*/]? *[0-9]+\.[0-9]|\.small\(\)|\.strong\(\)|\.heading\(|ui\.heading|\.monospace\('
if out=$(grep -nE "$pat" $files | grep -vE '^\S+:\s*//'); then
    echo "theme: style literals outside theme.rs:"; echo "$out"; exit 1
fi
echo "theme: OK ($(echo "$files" | wc -w) files)"
