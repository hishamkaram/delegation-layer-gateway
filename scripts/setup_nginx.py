#!/usr/bin/env python3
"""Preview or install an isolated Gateway virtual host on Ubuntu Nginx.

--hostname is required. Without --apply this only prints configuration. The
operator separately runs Certbot; this script never obtains keys or starts Gateway.
"""

from __future__ import annotations

import argparse
import contextlib
from dataclasses import dataclass
import fcntl
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile

SITES = Path("/etc/nginx/sites-enabled")
ACME = Path("/var/lib/delegation-layer-gateway-acme")
CA = Path("/etc/ssl/certs/ca-certificates.crt")
NGINX = "/usr/sbin/nginx"
SYSTEMCTL = "/usr/bin/systemctl"
MARKER = "# Managed by delegation-layer-gateway/scripts/setup_nginx.py\n"


@dataclass(frozen=True)
class Settings:
    hostname: str
    phase: str
    port: int = 9443

    def __post_init__(self) -> None:
        labels = self.hostname.split(".")
        if (
            len(self.hostname) > 253
            or len(labels) < 2
            or any(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None
                for label in labels
            )
        ):
            raise ValueError(
                "hostname must be a lowercase DNS name, without scheme, port or path"
            )
        if len(self.target.name.encode("ascii")) > 255:
            raise ValueError(
                "hostname is too long for the managed configuration filename"
            )
        if (
            self.phase not in ("bootstrap", "https")
            or not 1024 <= self.port <= 65535
            or self.port == 8443
        ):
            raise ValueError(
                "invalid phase or loopback port (8443 is reserved for direct device mTLS)"
            )

    @property
    def target(self) -> Path:
        return SITES / f"zzzz-delegation-layer-gateway-{self.hostname}.conf"

    @property
    def webroot(self) -> Path:
        return ACME / self.hostname

    def configuration(self) -> str:
        http = f"""server {{
    listen 80;
    server_name {self.hostname};
    access_log off;
    error_log /dev/null crit;
    if ($host != {self.hostname}) {{ return 444; }}
    location ^~ /.well-known/acme-challenge/ {{
        root {self.webroot};
        default_type text/plain;
        try_files $uri =404;
    }}
"""
        if self.phase == "bootstrap":
            return MARKER + http + "    location / { return 503; }\n}\n"
        routes = "\n".join(
            f"    location = {path} {{ proxy_pass https://127.0.0.1:{self.port}; }}"
            for path in (
                "/mcp",
                "/.well-known/oauth-protected-resource",
                "/.well-known/oauth-protected-resource/mcp",
                "/v1/enroll",
            )
        )
        return (
            MARKER
            + http
            + f"""    location / {{ return 308 https://{self.hostname}$request_uri; }}
}}
server {{
    listen 443 ssl;
    server_name {self.hostname};
    ssl_certificate /etc/letsencrypt/live/{self.hostname}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{self.hostname}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    access_log off;
    error_log /dev/null crit;
    if ($host != {self.hostname}) {{ return 444; }}
    client_max_body_size 1m;
    client_body_timeout 30s;
    send_timeout 310s;
    proxy_http_version 1.1;
    proxy_set_header Host {self.hostname};
    proxy_set_header Connection "";
    proxy_set_header Forwarded "";
    proxy_set_header X-Forwarded-For "";
    proxy_set_header X-Forwarded-Host "";
    proxy_set_header X-Forwarded-Proto "";
    proxy_set_header X-Real-IP "";
    proxy_ssl_server_name on;
    proxy_ssl_name {self.hostname};
    proxy_ssl_trusted_certificate {CA};
    proxy_ssl_verify on;
    proxy_ssl_verify_depth 5;
    proxy_ssl_protocols TLSv1.3;
    proxy_connect_timeout 5s;
    proxy_send_timeout 310s;
    proxy_read_timeout 310s;
    proxy_buffering off;
    proxy_cache off;
    proxy_next_upstream off;
    proxy_intercept_errors off;
{routes}
    location / {{ return 404; }}
}}
"""
        )


def command(arguments: list[str]) -> str:
    try:
        result = subprocess.run(
            arguments, check=False, capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"{arguments[0]} could not complete") from error
    if result.returncode:
        raise RuntimeError(
            f"{arguments[0]} failed (exit {result.returncode}); diagnostics withheld"
        )
    # Let Nginx's real parser detect conflicts, including quoted punctuation or
    # comments. Its conflicting-server-name warning otherwise has exit status 0.
    if "conflicting server name" in result.stderr.lower():
        raise RuntimeError(
            "nginx reports a conflicting server name; refusing activation"
        )
    return result.stdout


def protected_directory(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError(
            f"requires a root-owned directory without group/other writes: {path}"
        )


def existing_configuration(settings: Settings) -> bytes | None:
    try:
        info = settings.target.lstat()
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_nlink != 1
        or info.st_mode & 0o022
        or info.st_size > 65536
    ):
        raise RuntimeError("target must be an owned safe regular file, never a symlink")
    data = settings.target.read_bytes()
    text = data.decode("utf-8")
    ports = re.findall(r"proxy_pass https://127\.0\.0\.1:(\d+);", text)
    known = text == Settings(settings.hostname, "bootstrap").configuration()
    if ports and len(set(ports)) == 1:
        known = (
            text == Settings(settings.hostname, "https", int(ports[0])).configuration()
        )
    if not known:
        raise RuntimeError(
            "existing target differs from generated configuration; inspect it manually"
        )
    return data


def verify_included(dump: str, content: bytes) -> None:
    if dump.count(content.decode("utf-8")) != 1:
        raise RuntimeError("managed target is not included exactly once by nginx")


def sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def replace_configuration(target: Path, content: bytes) -> None:
    descriptor, name = tempfile.mkstemp(prefix=".gateway-nginx-", dir=target.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), 0o644)
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
        sync_directory(target.parent)
    finally:
        temporary.unlink(missing_ok=True)


def rollback(settings: Settings, previous: bytes | None, new: bytes) -> None:
    observed = settings.target.read_bytes() if settings.target.exists() else None
    if observed == previous:
        return
    if observed != new:
        raise RuntimeError("target changed concurrently; automatic rollback refused")
    if previous is None:
        settings.target.unlink()
        sync_directory(settings.target.parent)
    else:
        replace_configuration(settings.target, previous)
    command([NGINX, "-t"])
    command([SYSTEMCTL, "reload", "nginx"])


SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


@contextlib.contextmanager
def interruption_cleanup():
    def terminate(_number, _frame):
        raise InterruptedError("interrupted; installation rollback requested")

    previous = {number: signal.signal(number, terminate) for number in SIGNALS}
    try:
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def install(settings: Settings) -> None:
    if os.geteuid() != 0:
        raise RuntimeError("--apply requires sudo; preview does not")
    protected_directory(SITES)
    with contextlib.ExitStack() as stack:
        descriptor = os.open(SITES, os.O_RDONLY | os.O_DIRECTORY)
        stack.callback(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Ubuntu loads conf.d before sites-enabled. Appending after all existing
        # sites preserves their first/default server; never edit another vhost.
        if any(
            path != settings.target and path.name >= settings.target.name
            for path in SITES.iterdir()
        ):
            raise RuntimeError(
                "managed filename would not sort after existing sites; refusing default-site change"
            )
        previous = existing_configuration(settings)
        if (
            settings.phase == "bootstrap"
            and previous
            and b"listen 443 ssl;" in previous
        ):
            raise RuntimeError("refusing to downgrade an existing HTTPS virtual host")
        command([NGINX, "-t"])
        dump = command([NGINX, "-T"])
        if previous is not None:
            verify_included(dump, previous)
        if settings.phase == "https":
            for path in (
                CA,
                Path(f"/etc/letsencrypt/live/{settings.hostname}/fullchain.pem"),
                Path(f"/etc/letsencrypt/live/{settings.hostname}/privkey.pem"),
            ):
                if not path.is_file():
                    raise RuntimeError(f"required TLS file is missing: {path}")
        ACME.mkdir(mode=0o755, exist_ok=True)
        protected_directory(ACME)
        settings.webroot.mkdir(mode=0o755, exist_ok=True)
        protected_directory(settings.webroot)
        new = settings.configuration().encode()
        try:
            replace_configuration(settings.target, new)
            command([NGINX, "-t"])
            verify_included(command([NGINX, "-T"]), new)
            command([SYSTEMCTL, "reload", "nginx"])
        except BaseException:
            # Repeated termination cannot interrupt the bounded rollback commands.
            mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
            try:
                rollback(settings, previous, new)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--hostname", required=True, help="public DNS hostname; no scheme or path"
    )
    parser.add_argument("--phase", choices=("bootstrap", "https"), default="bootstrap")
    parser.add_argument("--upstream-port", type=int, default=9443)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="install, validate and reload; default is preview",
    )
    options = parser.parse_args()
    try:
        settings = Settings(options.hostname, options.phase, options.upstream_port)
        if options.apply:
            with interruption_cleanup():
                install(settings)
            print(
                f"Installed {settings.phase} virtual host; nginx validation/reload passed."
            )
            print(
                "Gateway startup, upstream TLS and external MCP remain separate checks."
            )
        else:
            print(settings.configuration(), end="")
    except (OSError, ValueError, RuntimeError) as error:
        print(f"setup_nginx: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
