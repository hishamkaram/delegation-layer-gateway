# Gateway implementation-candidate diagrams

These source-backed diagrams describe Gateway checkpoint
`96af53f7ca399d036c5b14461bd88d6ede5510c6`. Every node carries up to three
committed Gateway source ranges. Repository metadata preserves the
credential-free SSH origin and full revision; source links are **local-only**
because the checkpoint is unpublished. This is an implementation candidate,
not release approval.

| Diagram | Interactive HTML | Editable source | SVG export |
| --- | --- | --- | --- |
| Components, trust boundaries and authoritative owners | [Open](components.html) | [JSON](components.json) | [SVG](components.svg) |
| Admission, uncertainty, restore and CLI-routing ownership | [Open](operation-safety.html) | [JSON](operation-safety.json) | [SVG](operation-safety.svg) |

Gateway owns grants, immutable operation correlation and two separate resource
ledgers: uncertain Native execution reservations and durable routed-CLI permits.
Connector owns local aliases, frozen context pins and stricter execution
ceilings. Native/Delegate alone owns admission, launch, supervision and accepted
outcomes. Native nodes cite the Gateway **consumer boundary**, not Native
implementation at Gateway HEAD. Its public CLI remains an external prerequisite;
these artifacts do not establish future Native CWD/barrier corrections or
compatibility of another installed executable.

Public HTTPS OAuth/JWKS and device mTLS WSS use separate listener trust roles.
Connectors initiate outbound connections. Two device roles illustrate topology;
they do not prove two physical devices or networks. The same device account is
trusted, and a project grant is routing rather than an OS sandbox.

Schema 7 requires full prior-fleet routing coverage before **any** routed CLI.
Changed-process recovery uses an out-of-band frozen operator confirmation of
local CLI joins bound to current credential, process boot and exact connection
generation. It supplies no task-closure evidence. Closed older routing rows can
be compacted; active controls and uncertain task reservations remain retained.

Restore persists root barriers before inventory, conserves per-task canonical
identity/options and attributable/unattributed visibility, requires current
mapping/completeness and regular credentials before explicit reopen, then
verifies fresh root state before finish. Recovery-only credentials cannot
admit, resume or reopen. Current grants and authenticated connection identity
are rechecked around sends and response acceptance. The diagrams show related
procedures, not an automatic recovery engine.

The [architecture guide](../docs/architecture.md) owns the wider explanation;
[verification](../docs/verification.md) owns current evidence and open gates.
At the pinned checkpoint it records Go 1.27.4 `make check` and 151 Python tests.
The latest completed controlled local process run used Go 1.27.3; the newer
active-execution restart harness has not run live. These diagram checks do not
establish Native prerequisite completion, release readiness, real provider
accounts, ChatGPT Cloud acceptance or physical-device behavior.

## Regeneration

Use the [repository regeneration wrapper](../scripts/render_diagrams.py) from
the repository root. It needs Git, Node.js 18+, Python 3.12+ and a supported
installed Chrome/Chromium browser. First use fetches official Archify `v3.2.0`
source into the ignored `.local/tool-sources/archify` checkout and requires commit
`208acba8d412335185b2056fedf54b3405df43fb`. Later runs verify that source and
refuse unexpected edits. No installed executable is copied, hashed or modified;
no app dependency is added.

```sh
python3 scripts/render_diagrams.py
```

The wrapper applies the narrow [whitespace patch](../tools/archify-whitespace.patch)
before building with upstream `scripts/generate-viewer.mjs`. It removes only
template/export-CSS trailing whitespace before ordinary rendering/export.
Delivered HTML is not rewritten, and renderer checks remain intact.

For each diagram the wrapper runs normal showcase `finalize` with fresh browser
receipt paths, then production **Export → SVG · Auto** in a real browser. It
saves the canonical Blob with a final newline, parses XML, checks whitespace
and refreshes hash-bound maintained summaries. Keep source JSON, HTML, SVG and
summaries together. Raw receipts remain ignored private evidence; failed gates
stop regeneration without a success claim.

The wrapper owns and joins renderer/browser process groups on normal exit,
timeout and interruption. Linux uses a process-local
[child subreaper](https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html)
to join adopted browser descendants; other Unix hosts rely on their init reaper
and the same process-group emptiness gate. These are contributor-tool controls,
not a Gateway task engine. Native macOS regeneration remains unverified.

Generated viewers retain the Archify/Cocoon [MIT notice](../third_party/archify-LICENSE).
The renderer source pin owns that provenance.

## Validation and visual review

[Validation summary](validation.json) records exact current JSON/HTML hashes,
renderer revision, observed strict/browser gates and browser scope.
[SVG receipts](svg-exports.json) bind canonical exports to their source HTML.
Raw receipts contain local paths and are intentionally unpublished; maintained
paths are relative. These records describe a local run, not a new check on every
checkout.

The maintained [visual-review record](visual-review.json) distinguishes fresh
browser captures and image inspection from automated checks. SVG exports are
communication assets, not substitutes for checked HTML or runtime evidence.
