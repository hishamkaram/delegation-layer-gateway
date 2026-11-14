# Native-connect extension candidate diagrams

The editable sources describe committed Gateway checkpoint
`5693d910c971eb88b297aef32808bc9fc49046cf`. Both sources were regenerated with the maintained
renderer and passed normal strict/provenance/browser gates and canonical SVG
export. Fresh HTML/SVG images were inspected in both themes. The six-row
workflow needs vertical scrolling; the fixed navigation dock overlaps its last
row near the initial viewport edge, and scrolling reveals it fully.

Every node has at most three committed Gateway source ranges. Repository
metadata preserves the credential-free SSH origin and full revision with
`local-only` source links. The checkpoint is published; local-only links remain
an explicit authoring choice, not a claim that it is unpublished.

| Diagram | Editable source | Interactive HTML | SVG export |
| --- | --- | --- | --- |
| Owners, Native embedded client and local profile | [JSON](components.json) | [HTML](components.html) | [SVG](components.svg) |
| Enrollment, workspace resolution and task safety | [JSON](operation-safety.json) | [HTML](operation-safety.html) | [SVG](operation-safety.svg) |

Gateway schema 9 owns device ownership, live owner policy, resolution
correlations, execution reservations and durable CLI-routing permits. Legacy
wire-v1 devices retain explicit grants and alias pins. Wire v2 adds approved
workspace routing and immutable project handles; it does not add a task engine.
Native owns its default service host and embeds the public Gateway `deviceclient`
SDK. The SDK retains the existing connector runtime and joins its owners before
releasing identity. Expected SDK shutdown requires the SDK's direct qualified
Serve cancellation and clean Close; it establishes neither Native task closure
nor a successful Gateway connection. Session stop owns socket close before
canceling its read/write contexts, retains independent close diagnostics and
joins parent-cancellation hooks before reporting done. Operator flows for
OAuth/headless login, private browserless
tokens and local service/workspace controls belong in
[Native connect](../docs/native-connect.md).

Local profiles own workspace approvals, current ceilings and immutable pins.
Same request ID returns the first exact pin; changed selection conflicts. Gateway
keeps Native tokens opaque. Under the external Native path contract, new approvals
freeze canonical paths: replacing a directory at that same path preserves the
logical project. Native checks the canonical ancestor, relative containment and
frozen leaf path, then selects the current directory in the final child. A running
cwd stays with its opened directory; replacement alone does not invalidate an
accepted result. Legacy physical bindings retain their strict semantics, and
Native root, credential and process identities remain strict. These are Native
contract requirements, not implementation proof from Gateway source. Fresh
targeted capabilities precede execution, and the local policy lease covers
current-ceiling validation through CLI Start, then releases before Wait.
Periodic v2 metadata has at most 100 workspaces, not the retained project list.
Local pins include tombstones and have both 1,024-record and four-MiB encoded
budgets; Gateway independently caps resolution requests at 1,024/device,
including pending requests. Capacity reports reserve no slot, and identity is
not evicted to free capacity. Removed approvals block new resolution/admit/resume
while authorized saved task controls retain their frozen binding.

Native nodes cite Gateway's consumer boundary, never Native implementation at
Gateway HEAD. Native alone owns admission, launch, supervision, cancellation
and accepted outcomes. Required public features and service behavior need a
compatible Native implementation; Gateway source cannot prove another
installation's behavior. Gateway recognizes `connector-path-project-v1`; it
depends on both namespace features and `workspace-constrained-connector-v1`.
Workspace approval is routing policy in one trusted account, not an OS sandbox.

Separate public HTTPS OAuth/JWKS and device mTLS WSS listeners retain their trust
roles; devices initiate outbound connections. Full prior-fleet coverage precedes
any routed CLI. Census/ACK and frozen prior-CLI join attestations do not prove
task closure. Closed older routing records may compact while active controls and
uncertain execution reservations remain held. Restore keeps barrier, canonical
inventory, mapping/drain and guarded reopen ordering. Recovery-only credentials
cannot admit, resume or reopen. Scoped owned-root initialization does not bypass
active fleet restore or acquire general administration authority.

**This extension is not release-ready.** Its full integrated engineering gates,
extension live flows and final independent review remain pending. Historical MVP
process/provider/physical-device/Cloud acceptance remains scoped to its original
revisions. No obsolete test count or earlier pending-live statement is projected
onto the extension. The [architecture guide](../docs/architecture.md),
[verification ledger](../docs/verification.md) and
[release assessment](../docs/release-assessment.md) own those distinctions.

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

The [validation summary](validation.json) records current source/HTML hashes,
normal gates and renderer provenance. [SVG receipts](svg-exports.json) bind each
canonical export to its current HTML. The [visual-review record](visual-review.json)
binds actual image inspection to source/HTML/SVG hashes, including fresh light
and dark HTML captures at 1440×900 and 2048×1320, standalone SVG captures and
scrolled workflow captures. Supporting cards were also inspected at 2048×1320
in both themes. No delivered HTML/SVG was rewritten after receipt.

Labels and routes were readable at reviewed sizes. The workflow requires page
scrolling: the fixed navigation dock can overlap the last row at the initial
viewport edge; scrolling exposes it completely. SVG exports show all rows
without that dock but omit the HTML title/cards/source explorer. Supporting
cards continue below the figure; the interactive source explorer was not
visually inspected. This is scoped perceptual review, not an
accessibility audit, other-platform proof or runtime acceptance.

Keep JSON, HTML, SVG and byte-bound summaries together. Raw receipts/captures
remain private ignored evidence. Root owns final integrated docs/check gates;
diagram validation does not make the extension release-ready.
