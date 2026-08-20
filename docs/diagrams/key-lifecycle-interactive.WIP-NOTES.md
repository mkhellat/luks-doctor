# WIP: interactive pan/zoom/search for key-lifecycle.html

Not finished, not linked from any doc, not the file that ships
(`key-lifecycle.html` is still the static, working, linked version).
`key-lifecycle-interactive.html.wip` is the in-progress version with
this work. Rename `.wip` off and drop the old static file once this is
actually fixed and re-verified.

## What works

- Drag-to-pan (pointer events on `#diagram-viewport`).
- Zoom in/out buttons (`#diagram-zoom-in`/`#diagram-zoom-out`),
  scroll-wheel zoom.
- Search box (`#diagram-search`) correctly finds nodes by substring
  match against `g.node` text content in the rendered SVG.

## What's broken

**`fitToView()`'s scale/centering is wrong**, and by extension the
initial view and the "Fit" button are wrong. Root cause history, so
the next debugging pass doesn't repeat it:

1. First bug (fixed): the SVG had `width="100%"` plus a CSS
   `min-width: 1100px` on `.mermaid`, so the browser's own CSS was
   scaling the SVG independently of the JS transform — `state.scale`
   didn't correspond to a real 1:1 pixel size, breaking all the fit/
   zoom/jump math's assumptions. Fixed by adding `sizeSvgFromViewBox()`
   which sets explicit `width`/`height` attributes (and matching
   inline `style.width`/`height`) from the SVG's own `viewBox`, so the
   SVG always renders at its true intrinsic pixel size and *only* the
   JS transform controls apparent scale.

2. Second bug (NOT fixed): after (1), `fitToView()` still produces a
   wrong scale/position. Last measurement: viewBox was
   `6656.8 x 4728.6`, viewport was `930 x 638`, and the computed fit
   scale correctly floored at `minScale: 0.15` (roughly consistent
   with `930/6656 ≈ 0.14`) — so the *scale* number may actually be
   right. But the resulting view was NOT actually fit/centered on
   screen (see `fit-v3.png`-style screenshots taken this session,
   not saved to the repo — re-take if needed): the diagram appeared
   zoomed in on an off-center region, not zoomed out to show
   everything. And the search-jump centering check
   (`flashedCenter` vs `viewportCenter`) was off by ~200-450px in
   both x and y, not the near-exact match seen in an earlier (also
   since-invalidated) test.

   Suspect areas to check next:
   - `.diagram-pan-layer` is `display: inline-block` with
     `padding: 1.25rem` — confirm this padding isn't silently
     shifting the coordinate origin `jumpToNode()`/`fitToView()`
     assume is at the pan-layer's (0,0).
   - Whether `sizeSvgFromViewBox()` needs to run (and the browser
     needs a layout flush / `requestAnimationFrame` tick) *before*
     `viewport.getBoundingClientRect()` and `panLayer.getBoundingClientRect()`
     are read in the same tick — there may be a stale-layout race
     between setting the SVG's width/height attributes and reading
     positions derived from them.
   - Re-derive `jumpToNode()`'s coordinate math from scratch against
     the *fixed* `fitToView()`, rather than assuming the earlier
     "it matched exactly" test result still holds — that test was run
     before the intrinsic-sizing fix changed what `state.scale` means
     relative to on-screen pixels model-wide.
   - Consider abandoning the CSS-transform + manual-math approach
     entirely in favor of a small, well-tested pan-zoom library
     (e.g. `svg-pan-zoom` or `panzoom` via CDN) rather than
     hand-rolling the coordinate math a third time.

## How to test

This session used headless Chrome (`/usr/bin/google-chrome-stable`)
via `puppeteer-core`, driven from Node, with a small wrapper script
that reproduces how the Artifact platform wraps a published fragment
(full `<html>` + `mermaid.initialize()` module script). That
harness is not saved anywhere durable (it lived in the session's
`/tmp` scratchpad, which does not persist) — recreate it:

```js
// wrap a fragment file into a full doc + mermaid init, then screenshot
import fs from 'fs';
let html = fs.readFileSync('key-lifecycle-interactive.html.wip', 'utf8');
// NOTE: this file is already a full <!doctype html> document (the
// checked-in standalone copy), so for local testing just open it
// directly -- no wrapping needed. The wrap-then-init step above was
// only needed when testing the *Artifact-source* fragment (no
// <html>/<head>/<body>, no explicit mermaid.initialize() call)
// separately from the standalone copy.
```

Simplest repro: `google-chrome-stable --headless --no-sandbox
--screenshot=out.png file:///path/to/key-lifecycle-interactive.html.wip`
then inspect `out.png`, or drive it with `puppeteer-core` pointed at
`executablePath: '/usr/bin/google-chrome-stable'` for scripted
interaction (search box typing, click zoom buttons, drag-pan via
`page.mouse`).

## Do not link this file anywhere until fixed

`docs/af-splitting-explained.md` and the README should keep pointing
at `key-lifecycle.html` (the static version) until this WIP file
replaces it and is re-verified end to end.
