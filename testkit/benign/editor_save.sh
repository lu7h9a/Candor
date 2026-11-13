#!/usr/bin/env bash
# Editor-style save loop: swap file, write to a temp name, rename over the
# original, 200 times (what vim and most GUI editors do).
source "$(dirname "$0")/_common.sh"
if [ "$step" = setup ]; then printf 'notes\n' > notes.txt; exit 0; fi
for i in $(seq 1 200); do
    printf 'swap %d\n' "$i" > .notes.txt.swp
    { cat notes.txt; printf 'line %d\n' "$i"; } > notes.txt.tmp && mv notes.txt.tmp notes.txt
done
rm -f .notes.txt.swp
