# Gateway target-design diagrams

These maintained M0 artifacts describe the approved target design. They do not
claim that Gateway or the proposed Delegate connector contract is implemented.
The approved implementation contract v7 is the planning source; repository
[architecture documentation](../docs/architecture.md) owns the reconciled design.

| Diagram | Interactive HTML | Editable source | SVG export |
| --- | --- | --- | --- |
| Components, trust boundaries and authoritative owners | [Open](components.html) | [JSON](components.json) | [SVG](components.svg) |
| Admission, permanent refusal, restore and revocation | [Open](operation-safety.html) | [JSON](operation-safety.json) | [SVG](operation-safety.svg) |

Gateway owns grants, correlations and routing quota. Connector owns pinned local
aliases and its policy ceiling. Delegate alone owns task admission/refusal,
execution and accepted results. Restore keeps admission disabled until every
destination applies a durable generation barrier, complete canonical inventory
reconstructs accounting, and local admin explicitly reopens with current proof.

Proposed Delegate changes belong in a dedicated Delegate worktree and use its
own harness. The pre-PR gate is independent integrated review with no known
unresolved P0/P1/P2; diagram checks do not satisfy implementation or live gates.

## Regeneration

Use the [repository regeneration wrapper](../scripts/render_diagrams.py) from
the repository root. It needs Git, Node.js 18+, Python 3.12+ and a supported
installed Chrome/Chromium browser. First use fetches the official Archify
`v3.2.0` source into the ignored `.local/tool-sources/archify` checkout and
requires commit `208acba8d412335185b2056fedf54b3405df43fb`. Subsequent use verifies
that source and refuses unexpected edits. No installed executable is copied,
hashed or modified, and no app dependency is added.
The wrapper uses POSIX process groups and file locking; this delivery exercised
it on the current Linux host and does not establish native macOS behavior.

```sh
python3 scripts/render_diagrams.py
```

The wrapper applies the narrow [whitespace patch](../tools/archify-whitespace.patch)
to source and builds the viewer using upstream `scripts/generate-viewer.mjs`.
It removes template-only trailing whitespace before rendering and trailing
whitespace from the canonical export's generated CSS. It does not rewrite
delivered HTML or weaken a renderer/check. This repairs the observed upstream
formatting defect while preserving ordinary delivery provenance.

For each diagram the wrapper runs the candidate's normal `finalize` command
with showcase quality and a fresh `--out-dir`, serially. It then invokes the
production **Export → SVG · Auto** behavior in a real browser, captures the
canonical Blob, saves it with a final newline, parses XML, checks whitespace
and refreshes the maintained summaries from current receipts. HTML paths stay
stable. Keep JSON, HTML, SVG and summaries together; raw Archify receipts stay
ignored local evidence. Failed gates stop regeneration without a success claim.

The wrapper owns and joins its renderer process groups on normal exit, timeout
and interruption. Linux uses the documented process-local
[child subreaper](https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html)
facility to adopt and reap orphaned browser children. Other Unix hosts use their
init reaper; the wrapper retains its lease until its process group is empty.
These controls belong only to this contributor tool, not Gateway task execution.
Native Linux normal, interruption and stubborn-descendant regressions passed;
native macOS regeneration remains unverified.

Generated interactive viewers include Archify/Cocoon software under the retained
[MIT notice](../third_party/archify-LICENSE). The renderer source pin above owns
that provenance; no installed executable is copied into this repository.

## Validation evidence

Both final `finalize` commands exited 0. Each passed schema/layout validation,
delivery, all nine strict artifact checks and the real-browser gate. Browser
checks cover light theme at 1440×900, 1600×1000, 1920×1080 and 2048×1320, dark
theme at the endpoints, and READ/Still runtime states. No perceptual visual
review was requested or claimed.

- Both diagrams: [maintained validation summary](validation.json), including
  current source/HTML hashes, observed gates, Archify version and browser scope.
- SVG: [canonical export receipts and XML parse checks](svg-exports.json).

Raw receipts include machine-local paths and are intentionally unpublished.
The maintained summary uses relative artifact paths and records the successful
local checks; it does not make a fresh checkout a new validation run.

SVG exports are communication assets, not substitutes for checked HTML or
implementation evidence. Runtime export reported canonical state clean; saved
exports were parsed as XML and hashed. No paid provider, external deployment,
device execution or cloud-client acceptance was tested by this diagram work.
