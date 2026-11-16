# Bundled fonts

Static instances of two variable fonts, Latin subset, bundled into
`candor-gui` with `include_bytes!` (never downloaded at run time):

| File | Family, weight | Licence |
|---|---|---|
| Inter-Regular.ttf, Inter-Medium.ttf, Inter-SemiBold.ttf | Inter 4.001, 400 / 500 / 600 | SIL OFL 1.1, OFL-Inter.txt |
| JetBrainsMono-Regular.ttf, JetBrainsMono-Medium.ttf | JetBrains Mono 2.211, 400 / 500 | SIL OFL 1.1, OFL-JetBrainsMono.txt |

Source: the Google Fonts Latin subsets (U+0000-00FF and common punctuation)
embedded in the owner's design file (docs/design/mockups/), cut to fixed
weights with `fontTools.varLib.instancer`. Characters outside the subset
fall back to egui's built-in fonts.
