# Remote Delegate candidate diagrams

The editable sources describe Gateway source checkpoint
`751a59e24f17e3afbe2c2a3394557b822a03a4bf`. The maintained renderer regenerated
both HTML/SVG artifacts and passed normal validation, delivery, artifact and
browser gates with current provenance, plus canonical SVG export, XML and
whitespace checks. Actual visual review covered 14 fresh images, including both
HTML themes at two sizes, the scrolled workflow and both SVG themes. The fixed
navigation dock overlaps part of the workflow's last row in the initial viewport;
scrolling reveals it fully. The review's exact scope and limits are recorded below.

Every node has at most three Gateway source ranges. External Native nodes cite
Gateway's consumer contracts, never Native implementation at Gateway HEAD.
Repository metadata retains the credential-free SSH origin and `local-only`
source links. Root owns the checkpoint, regenerated artifacts and final review.

| Diagram | Editable source | Interactive HTML | SVG export |
| --- | --- | --- | --- |
| Gateway, local profile and Native execution owners | [JSON](components.json) | [HTML](components.html) | [SVG](components.svg) |
| Browse, immutable preparation and task safety | [JSON](operation-safety.json) | [HTML](operation-safety.html) | [SVG](operation-safety.svg) |

Gateway schema 10 owns immutable device ownership, current access policy,
request correlations, execution reservations and durable CLI-routing permits.
Explicit migration removes obsolete duplicate execution ceilings while
preserving frozen historical operation bytes. The local profile owns workspace
approvals, credentials and legacy alias pins. Native alone owns execution-option
support, defaults and validation, admission, sessions, lifecycle and accepted
outcomes. Discovery is dated advice, never an execution allowlist.

The normal route browses approved workspaces and Native's automatic whole OS
temp scopes: Linux `/tmp`; macOS per-user temp and shared `/private/tmp`,
canonicalized and deduplicated. `list_directory`, `read_file` and `inspect_git`
obtain bounded live Native observations. Requested names and bytes remain exact
authorized response data and stay out of diagnostics. Git candidates establish
structure, not validated repository identity. Reads and passive selection create
no project pin, task or admission namespace. The Gateway keeps local absolute
paths and CLI tokens behind the connector boundary.

`prepare_dispatch` retains an explicit device, scope-relative selector, stable
client request ID and Native option omissions. Replay lookup precedes live
selection and identity allocation. `prepare_continuation` freezes one typed
successor and exact predecessor guards; omitted selection, brief and options
inherit. Only budget/model/effort/output-silence overrides are accepted; Native
decides saved-session eligibility. `dispatch_task` confirms the saved draft.
New work checks current local approval through CLI Start, then releases that
lease before Wait. Native owns directory custody and
canonical-path semantics; same-path replacement does not move a running cwd.
See [the preparation contract](../docs/contracts.md#scope-relative-preparation).

Legacy `resolve_project` remains a separate alias compatibility route. Same
request ID returns the first exact pin; changed selection conflicts. Its local
pins include tombstones and retain 1,024-record and four-MiB encoded budgets.
Gateway independently retains 1,024 resolution requests/device, including
pending requests. Periodic v2 metadata carries at most 100 workspaces and a dated
legacy pin budget, never the retained project list. Capacity observations reserve
no slot; identity is never evicted to free capacity. Legacy physical bindings
and strict Native root, credential and process identities keep their existing
guards.

Compact immutable Origin binding commits request kind, identities, captured
route, client key, input digest and requested brief presence/digest; a successor
also commits its predecessor. Requested Native options have one authority in the
retained Gateway request body. Canonical inventory restores task correlations
and permanent refusal tombstones; invalid or wrong-owner binding rejects the
whole page. After body disposal, stable replay and historical controls remain
possible, including canonical existing-only recovery; fresh admission is
forbidden. Historical v2/v3 digests and missing-binding rules stay intact.
Current authority is always checked independently. See
[compact intent and recovery](../docs/contracts.md#compact-intent-and-registry-loss-recovery).

Native owns its default service host and embeds the public Gateway `deviceclient`
SDK. The SDK retains the connector runtime and joins its owners before releasing
identity. Expected SDK shutdown needs direct qualified Serve cancellation and
clean Close; it establishes neither Native task closure nor successful Gateway
connection. Session stop closes the socket before canceling read/write contexts,
retains independent close diagnostics and joins parent-cancellation hooks before
reporting done. Operator OAuth/headless login, private browserless tokens and
local service controls belong in [Native connect](../docs/native-connect.md).

Separate public HTTPS OAuth/JWKS and device mTLS WSS listeners retain their trust
roles; devices connect outbound. Current token scopes intersect owner policy or
legacy grants. Workspace and automatic temp scopes are routing boundaries in one
trusted account, never an OS sandbox. Missing required executable capabilities
fail explicitly. Native implementation and installed-provider behavior need
separate proof; source contracts do not establish them.

Full prior-fleet coverage precedes routed CLI controls. Census/ACK and frozen
prior-CLI join attestations never prove task closure. Routing permits stay held
through actual Wait and cleanup. Canonical closure, exact confirmed stop or
permanent refusal can release execution reservations; accepted result bytes,
timeout, socket closure and routing completion cannot. Restore retains barrier,
canonical inventory, mapping/drain and guarded reopen ordering. Recovery-only
credentials cannot admit, resume or reopen. Scoped owned-root initialization
does not bypass active fleet restore or acquire general administration authority.

**This candidate is not release-ready.** The dated Linux actual-process
filesystem and compact-dispatch literal-provider fixture proofs passed; later
protected-message sizing changes are outside that process checkpoint.
Installed-provider continuation, native macOS/original device states, physical
networks, actual Cloud clients and seven elapsed days of refresh/idle return
remain unverified. Complete engineering gates and final independent review are
pending. Historical MVP acceptance stays scoped to its original revisions. The
[verification ledger](../docs/verification.md),
[architecture guide](../docs/architecture.md) and
[release assessment](../docs/release-assessment.md) own these distinctions.

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

The [validation summary](validation.json) binds the current source/HTML hashes
and successful normal renderer/browser gates. [SVG receipts](svg-exports.json)
bind each canonical export to its current HTML. The
[visual-review record](visual-review.json) binds this actual image inspection to
checkpoint `751a59e24f17e3afbe2c2a3394557b822a03a4bf` and the current
source/HTML/SVG hashes.

Fourteen images were inspected: each HTML figure at 1440×900 and 2048×1320 in
light and dark themes, the workflow scrolled 420px at 1440×900 in both themes,
and each standalone SVG at 1600×1200 under both emulated themes. Updated labels
and routes were readable in those figure areas, without observed label clipping
or route-through-node collision. The workflow's fixed navigation dock obscures
part of the final row in the initial viewport; the scrolled captures show that
row and legend fully. Both SVG figures show all nodes and routes without the dock.

Supporting cards were only partly visible and were not fully reviewed. The
interactive source explorer was not visually inspected. SVG omits the HTML
title, cards and source explorer. This review covers only the listed images,
Chrome, sizes and themes; it is not an accessibility audit, other-platform
proof or runtime acceptance.

Keep JSON, HTML, SVG and byte-bound summaries together. Diagram JSON, HTML, SVG
and generated render/export receipts stayed unchanged during this visual review.
Raw captures and browser receipts remain private ignored evidence. Root owns
final integrated docs/check gates; diagram validation does not make the
candidate release-ready.
