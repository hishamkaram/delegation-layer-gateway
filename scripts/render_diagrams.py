#!/usr/bin/env python3
"""Regenerate checked diagrams from a pinned, locally patched Archify source."""

from __future__ import annotations

import fcntl
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / ".local/tool-sources/archify"
REMOTE = "https://github.com/tt-a1i/archify.git"
REVISION = "208acba8d412335185b2056fedf54b3405df43fb"
TAG = "v3.2.0"
PATCH = ROOT / "tools/archify-whitespace.patch"
PATCHED = ["archify/renderers/shared/cli.mjs", "viewer/export.js"]
GENERATED = "archify/assets/template.html"
DIAGRAMS = (("components", "architecture"), ("operation-safety", "workflow"))


def interrupted(_signal: int, _frame: object) -> None:
    """Route terminal/service interruption through the owned-child join path."""
    raise KeyboardInterrupt


def adopt_owned_orphans() -> None:
    """On Linux, retain Wait ownership when the pinned browser double-forks.

    This affects only this short-lived contributor process, never Gateway or
    Delegate. See Linux PR_SET_CHILD_SUBREAPER(2const). Other Unix hosts rely on
    their init reaper and the same final process-group emptiness check.
    """
    if sys.platform == "linux":
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.argtypes = [
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        ]
        prctl.restype = ctypes.c_int
        if prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER since Linux3.4.
            raise OSError(ctypes.get_errno(), "cannot own browser descendant cleanup")


def reap_group(group: int, *, wait: bool) -> None:
    while True:
        try:
            pid, _status = os.waitpid(-group, 0 if wait else os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def group_exists(group: int) -> bool:
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    return True


def stop_owned_group(child: subprocess.Popen[str]) -> None:
    """Escalate independently of pipe/direct-child exit, then join the child."""
    blocked = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
    try:
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass  # No members remain in the owned group.
        # Do not reap the leader during the grace period: its PID keeps the
        # group identity reserved while descendants close their own resources.
        time.sleep(1)
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # No members remain in the owned group.
        child.communicate()
        reap_group(child.pid, wait=True)
        # A non-Linux init may need a scheduling turn to reap its descendants.
        # Keep the lease and interruption mask until no group members remain.
        while group_exists(child.pid):
            time.sleep(0.01)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


# Exercise the production Export menu; intercept only the download boundary.
# ChromeVisualBrowser is the same source-owned transport used by Archify tests.
EXPORT = r"""
import fs from 'node:fs';
import {pathToFileURL} from 'node:url';
const [source, html, output] = process.argv.slice(2);
const {ChromeVisualBrowser, findChrome} = await import(pathToFileURL(source + '/archify/bin/visual-check.mjs'));
const chrome = findChrome();
if (!chrome) throw new Error('No supported Chrome browser available for SVG export');
const browser = new ChromeVisualBrowser(chrome);
try {
  const session = await browser.sessionPromise;
  const send = (method, params = {}) => browser.cdp.send(method, params, session);
  const evaluate = async expression => {
    const result = await send('Runtime.evaluate', {expression, awaitPromise:true, returnByValue:true});
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || 'SVG export evaluation failed');
    return result.result?.value;
  };
  const loaded = browser.cdp.waitFor('Page.loadEventFired', session);
  await send('Page.navigate', {url:pathToFileURL(html).href});
  await loaded;
  await evaluate('document.fonts.ready.then(() => true)');
  await evaluate('Archify.readerLayout.whenStable().then(() => true)');
  const exported = await evaluate(`(async () => {
    let blob;
    const create = URL.createObjectURL;
    const click = HTMLAnchorElement.prototype.click;
    URL.createObjectURL = value => { blob = value; return create(value); };
    HTMLAnchorElement.prototype.click = () => {};
    try {
      await Archify.exportMenu.run('svg');
      if (!blob || document.documentElement.getAttribute('data-last-export-canonical') !== 'true')
        throw new Error('Canonical SVG export failed');
      return {svg:await blob.text(), bytes:blob.size, canonical:true};
    } finally {
      URL.createObjectURL = create;
      HTMLAnchorElement.prototype.click = click;
    }
  })()`);
  fs.writeFileSync(output, exported.svg + '\n');
  console.log(JSON.stringify({runtimeReportedBytes:exported.bytes, runtimeCanonicalStateClean:exported.canonical}));
} finally {
  await browser.close();
}
"""


def run(args: list[str], *, cwd: Path = ROOT, stdin: str | None = None) -> str:
    adopt_owned_orphans()
    previous = {
        number: signal.getsignal(number)
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    }
    pending = False
    child: subprocess.Popen[str] | None = None

    def defer_interruption(_signal: int, _frame: object) -> None:
        # Do not raise between fork/exec and the caller receiving its handle.
        # Unlike a blocked signal mask, this does not alter the child's mask.
        nonlocal pending
        pending = True

    try:
        for number in previous:
            signal.signal(number, defer_interruption)
        child = subprocess.Popen(
            args,
            cwd=cwd,
            text=True,
            stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        # Handle acquisition is now inside guaranteed cleanup. Restore the
        # caller's policy, then deliver any interruption recorded at Start.
        for number, handler in previous.items():
            signal.signal(number, handler)
        if pending:
            raise KeyboardInterrupt
        stdout, stderr = child.communicate(stdin, timeout=300)
        reap_group(child.pid, wait=False)
        if group_exists(child.pid):
            stop_owned_group(child)
    except BaseException:
        if child is not None:
            stop_owned_group(child)
        raise
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    if child.returncode:
        raise RuntimeError(
            f"{args[0]} {args[1:4]} failed ({child.returncode}): "
            f"{stderr[-6000:]} {stdout[-6000:]}"
        )
    return stdout


def identity(file: Path) -> dict[str, str | int]:
    data = file.read_bytes()
    return {
        "path": file.name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }


def candidate() -> Path:
    if not SOURCE.exists():
        SOURCE.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "clone", "--depth", "1", "--branch", TAG, REMOTE, str(SOURCE)])
    if run(["git", "rev-parse", "HEAD"], cwd=SOURCE).strip() != REVISION:
        raise RuntimeError(
            "Owned Archify checkout has the wrong revision; preserve it and resolve explicitly"
        )
    if run(["git", "remote", "get-url", "origin"], cwd=SOURCE).strip() != REMOTE:
        raise RuntimeError("Owned Archify checkout has an unexpected origin")
    package = json.loads((SOURCE / "archify/package.json").read_text())
    if package["version"] != "3.2.0":
        raise RuntimeError("Source package version differs from the pinned release")
    changed = set(run(["git", "diff", "HEAD", "--name-only"], cwd=SOURCE).splitlines())
    if changed - {*PATCHED, GENERATED}:
        raise RuntimeError(
            "Unexpected local Archify changes; preserve and inspect them before regeneration"
        )
    if run(["git", "ls-files", "--others", "--exclude-standard"], cwd=SOURCE).strip():
        raise RuntimeError("Unexpected untracked Archify source files")
    current_patch = run(
        ["git", "diff", "HEAD", "--unified=0", "--", *PATCHED], cwd=SOURCE
    )
    if not current_patch:
        run(["git", "apply", "--check", "--unidiff-zero", str(PATCH)], cwd=SOURCE)
        run(["git", "apply", "--unidiff-zero", str(PATCH)], cwd=SOURCE)
    elif current_patch != PATCH.read_text():
        raise RuntimeError(
            "Archify changes differ from the maintained whitespace patch"
        )
    run(["node", "scripts/generate-viewer.mjs"], cwd=SOURCE)
    run(["node", "scripts/generate-viewer.mjs", "--check"], cwd=SOURCE)
    return SOURCE / "archify/bin/archify.mjs"


def render() -> None:
    cli = candidate()
    directory = ROOT / "diagrams"
    validations = []
    exports = []
    renderer = {
        "repository": REMOTE,
        "tag": TAG,
        "commit": REVISION,
        "version": "3.2.0",
        "localPatch": "../tools/archify-whitespace.patch",
        "patchSha256": identity(PATCH)["sha256"],
        "build": "node scripts/generate-viewer.mjs (in owned source checkout)",
    }
    for stem, kind in DIAGRAMS:
        # Every revision gets fresh browser evidence; no old receipt is relabeled.
        revision = 1
        while (directory / f"{stem}.source-review-{revision}").exists():
            revision += 1
        evidence = directory / f"{stem}.source-review-{revision}"
        print(f"Rendering and checking {stem}", flush=True)
        command = [
            "node",
            str(cli),
            "finalize",
            kind,
            f"diagrams/{stem}.json",
            f"diagrams/{stem}.html",
            "--quality",
            "showcase",
            "--out-dir",
            str(evidence),
            "--json",
        ]
        summary = json.loads(run(command))
        full = json.loads((evidence / f"{stem}.finalize.json").read_text())
        browser = json.loads((evidence / f"{stem}.browser-check.json").read_text())
        source = identity(directory / f"{stem}.json")
        html = identity(directory / f"{stem}.html")
        if not summary["ok"] or any(v != "pass" for v in summary["gates"].values()):
            raise RuntimeError(f"{stem}: incomplete Archify gates")
        for observed, recorded in [
            (source, summary["specification"]),
            (html, summary["artifact"]),
            (html, browser["artifact"]),
        ]:
            if any(observed[key] != recorded[key] for key in ["sha256", "bytes"]):
                raise RuntimeError(
                    f"{stem}: current artifact does not match its receipt"
                )
        exported = json.loads(
            run(
                [
                    "node",
                    "--input-type=module",
                    "-",
                    str(SOURCE),
                    str(directory / f"{stem}.html"),
                    str(directory / f"{stem}.svg"),
                ],
                stdin=EXPORT,
            )
        )
        ET.parse(directory / f"{stem}.svg")
        for extension in ["html", "svg"]:
            if any(
                line.endswith((b" ", b"\t"))
                for line in (directory / f"{stem}.{extension}")
                .read_bytes()
                .splitlines()
            ):
                raise RuntimeError(
                    f"{stem}.{extension}: trailing whitespace remains; do not claim formatting passed"
                )
        exports.append(
            {
                "artifact": f"{stem}.svg",
                **{
                    k: v
                    for k, v in identity(directory / f"{stem}.svg").items()
                    if k != "path"
                },
                **exported,
                "method": "Production canonical SVG Auto export; saved with final newline",
                "format": "svg",
                "xmlParse": "pass",
                "sourceHtmlSha256": html["sha256"],
            }
        )
        validations.append(
            {
                "id": stem,
                "diagramType": kind,
                "qualityProfile": "showcase",
                "renderer": renderer,
                "startedAt": full["startedAt"],
                "finishedAt": full["finishedAt"],
                "exitCode": 0,
                "source": source,
                "html": html,
                "gates": summary["gates"],
                "validation": full["stages"]["validate"]["receipt"]["validation"],
                "artifactCheckCount": len(full["stages"]["check"]["receipt"]["checks"]),
                "browserEvidence": {
                    "kind": browser["evidenceKind"],
                    "status": browser["status"],
                    "artifactSha256": browser["artifact"]["sha256"],
                    "state": browser["state"],
                    "provenance": browser["provenance"],
                    "containment": browser["containment"]["status"],
                    "readability": browser["readability"]["status"],
                    "viewerChrome": browser["viewerChrome"]["status"],
                    "themeStates": browser["themeStates"],
                    "visualReview": browser["visualReview"],
                },
                "svgExport": {"path": f"{stem}.svg", "receipt": "svg-exports.json"},
            }
        )
    for filename, value in [
        (
            "svg-exports.json",
            {
                "scope": "Diagram communication assets only; no implementation or perceptual approval claim",
                "renderer": renderer,
                "exports": exports,
            },
        ),
        (
            "validation.json",
            {
                "schemaVersion": 1,
                "scope": "Observed local source-candidate Archify checks; target design only",
                "pathBase": "Directory containing this file",
                "recipe": "../scripts/render_diagrams.py",
                "limitations": [
                    "Automated checks only; no perceptual visual review",
                    "No Gateway/Delegate behavior, device/provider execution, cloud acceptance or release readiness established",
                    "Raw local receipts are unpublished; this summary does not rerun validation on checkout",
                ],
                "diagrams": validations,
            },
        ),
    ]:
        (directory / filename).write_text(json.dumps(value, indent=2) + "\n")
    print(
        "Both diagrams: normal finalize/provenance/browser gates, canonical SVG export, XML and whitespace checks passed"
    )


def main() -> int:
    for terminating_signal in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(terminating_signal, interrupted)
    try:
        # One wrapper owns the source mutation/build and serial artifact delivery.
        # flock releases on exit/crash; retaining the lock file avoids unlink races.
        (ROOT / ".local").mkdir(exist_ok=True)
        with (ROOT / ".local/render-diagrams.lock").open("a") as lease:
            try:
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise RuntimeError(
                    "Another diagram regeneration owns the local source/output lease"
                ) from error
            render()
    except (
        OSError,
        ValueError,
        RuntimeError,
        subprocess.TimeoutExpired,
        ET.ParseError,
    ) as error:
        print(f"Diagram regeneration failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
