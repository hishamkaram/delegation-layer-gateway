"""Protect operator isolation, rollback, real Nginx parsing and default routing."""

from __future__ import annotations

import http.client
import os
from pathlib import Path
import shutil
import signal
import stat
import socket
import subprocess
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import setup_nginx as setup

TEST_HOST = "gateway.example.com"


class NginxSetupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.sites = self.root / "sites"
        self.sites.mkdir()
        patcher = patch.multiple(setup, SITES=self.sites, ACME=self.root / "acme")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.settings = setup.Settings(TEST_HOST, "bootstrap")
        self.target = self.settings.target

    def test_tls_configuration_has_fixed_routes_and_no_unsafe_proxy_defaults(
        self,
    ) -> None:
        config = setup.Settings(TEST_HOST, "https").configuration()
        for required in (
            "proxy_ssl_verify on;",
            f"proxy_ssl_name {TEST_HOST};",
            "proxy_ssl_server_name on;",
            "proxy_ssl_protocols TLSv1.3;",
            "proxy_next_upstream off;",
            "proxy_buffering off;",
            "proxy_set_header X-Real-IP $remote_addr;",
            "access_log off;",
            "error_log /dev/null crit;",
            "location = /mcp",
            "location = /v1/enroll",
            "location = /.well-known/oauth-protected-resource/mcp",
            "location = /.well-known/delegation-gateway",
            "location = /v1/self/enroll",
            "location = /v1/self/devices/revoke",
            "location / { return 404; }",
        ):
            self.assertIn(required, config)
        self.assertNotIn("8443", config)
        self.assertNotIn("ssl_verify off", config)
        self.assertNotIn("default_server", config)
        for port in (0, 443, 8443, 65536):
            with self.assertRaises(ValueError):
                setup.Settings(TEST_HOST, "https", port)
        for host in (
            "x;return 200",
            "https://example.com",
            "x.example.com\n",
            "*.example.com",
            "../example.com",
            "example.com/path",
            ".".join(["a" * 62] * 4),
        ):
            with self.assertRaises(ValueError):
                setup.Settings(host, "https")

    def test_foreign_config_or_symlink_is_never_replaced(self) -> None:
        self.target.write_text("# foreign site\n")
        with self.assertRaises(RuntimeError):
            setup.existing_configuration(self.settings)
        other = self.root / "other"
        other.write_text("keep")
        self.target.unlink()
        self.target.symlink_to(other)
        with self.assertRaises(RuntimeError):
            setup.existing_configuration(self.settings)
        self.assertEqual(other.read_text(), "keep")

    def test_exact_legacy_vhost_can_upgrade_but_edited_legacy_is_refused(self) -> None:
        settings = setup.Settings(TEST_HOST, "https")
        current = settings.configuration(forward_client_ip=False)
        legacy = current
        for path in (
            "/.well-known/delegation-gateway",
            "/v1/self/enroll",
            "/v1/self/devices/revoke",
        ):
            legacy = legacy.replace(
                f"    location = {path} {{ proxy_pass https://127.0.0.1:9443; }}\n",
                "",
            )
        self.assertNotEqual(legacy, current)
        self.assertEqual(
            settings.configuration(native_login=False, forward_client_ip=False), legacy
        )
        self.target.write_text(legacy)
        owned = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o644,
            st_uid=0,
            st_nlink=1,
            st_size=len(legacy),
        )
        with patch.object(Path, "lstat", return_value=owned):
            self.assertEqual(setup.existing_configuration(settings), legacy.encode())
            self.target.write_text(legacy.replace("ssl_verify on;", "ssl_verify off;"))
            with self.assertRaises(RuntimeError):
                setup.existing_configuration(settings)

    def test_exact_native_vhost_before_client_ip_forwarding_can_upgrade(self) -> None:
        settings = setup.Settings(TEST_HOST, "https")
        prior = settings.configuration(forward_client_ip=False)
        self.target.write_text(prior)
        owned = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o644, st_uid=0, st_nlink=1, st_size=len(prior)
        )
        with patch.object(Path, "lstat", return_value=owned):
            self.assertEqual(setup.existing_configuration(settings), prior.encode())
            self.target.write_text(
                prior.replace('X-Real-IP "";', "X-Real-IP $http_x_real_ip;")
            )
            with self.assertRaises(RuntimeError):
                setup.existing_configuration(settings)

    def test_exact_once_inclusion_is_required(self) -> None:
        content = self.settings.configuration().encode()
        setup.verify_included(content.decode(), content)
        for dump in ("", content.decode() * 2):
            with self.assertRaises(RuntimeError):
                setup.verify_included(dump, content)

    def test_ignored_candidate_is_removed_before_activation(self) -> None:
        commands: list[list[str]] = []

        def run(arguments: list[str]) -> str:
            commands.append(arguments)
            return ""

        with (
            patch.object(setup.os, "geteuid", return_value=0),
            patch.object(setup, "protected_directory"),
            patch.object(setup, "command", side_effect=run),
        ):
            with self.assertRaisesRegex(RuntimeError, "included exactly once"):
                setup.install(self.settings)
        self.assertFalse(self.target.exists())
        self.assertEqual(commands.count([setup.SYSTEMCTL, "reload", "nginx"]), 1)

    def test_validation_failure_restores_prior_bytes_and_reloads_prior_config(
        self,
    ) -> None:
        prior = b"prior-image\n"
        self.target.write_bytes(prior)
        calls: list[list[str]] = []

        def run(arguments: list[str]) -> str:
            calls.append(arguments)
            current = self.target.read_bytes()
            if arguments == [setup.NGINX, "-t"] and current != prior:
                raise RuntimeError("candidate invalid")
            return current.decode() if arguments == [setup.NGINX, "-T"] else ""

        with (
            patch.object(setup.os, "geteuid", return_value=0),
            patch.object(setup, "protected_directory"),
            patch.object(setup, "existing_configuration", return_value=prior),
            patch.object(setup, "command", side_effect=run),
        ):
            with self.assertRaisesRegex(RuntimeError, "candidate invalid"):
                setup.install(self.settings)
        self.assertEqual(self.target.read_bytes(), prior)
        self.assertEqual(
            calls[-2:], [[setup.NGINX, "-t"], [setup.SYSTEMCTL, "reload", "nginx"]]
        )
        self.assertFalse(list(self.sites.glob(".gateway-nginx-*")))

    def test_failed_reload_removes_only_its_own_vhost(self) -> None:
        foreign = self.sites / "app.conf"
        foreign.write_bytes(b"other virtual host")
        reloads = 0

        def run(arguments: list[str]) -> str:
            nonlocal reloads
            if arguments == [setup.SYSTEMCTL, "reload", "nginx"]:
                reloads += 1
                if reloads == 1:
                    raise RuntimeError("reload failed")
            if arguments == [setup.NGINX, "-T"] and self.target.exists():
                return self.target.read_text()
            return ""

        with (
            patch.object(setup.os, "geteuid", return_value=0),
            patch.object(setup, "protected_directory"),
            patch.object(setup, "command", side_effect=run),
        ):
            with self.assertRaisesRegex(RuntimeError, "reload failed"):
                setup.install(self.settings)
        self.assertFalse(self.target.exists())
        self.assertEqual(foreign.read_bytes(), b"other virtual host")
        self.assertEqual(reloads, 2)

    def test_later_sorting_site_refuses_before_any_command(self) -> None:
        (self.sites / "zzzzz-foreign.conf").write_text("keep")
        with (
            patch.object(setup.os, "geteuid", return_value=0),
            patch.object(setup, "protected_directory"),
            patch.object(setup, "command") as command,
        ):
            with self.assertRaisesRegex(RuntimeError, "default-site change"):
                setup.install(self.settings)
            command.assert_not_called()
        self.assertFalse(self.target.exists())

    def test_preview_performs_no_commands_or_filesystem_mutation(self) -> None:
        with (
            patch.object(
                setup.sys,
                "argv",
                ["setup_nginx.py", "--hostname", TEST_HOST, "--phase", "https"],
            ),
            patch.object(setup, "command") as command,
            patch("builtins.print"),
        ):
            self.assertEqual(setup.main(), 0)
            command.assert_not_called()
        self.assertFalse(self.target.exists())
        self.assertFalse((self.root / "acme").exists())

    def test_handled_signals_unwind_and_restore_callers_handlers(self) -> None:
        for number in setup.SIGNALS:
            before = signal.getsignal(number)
            with self.assertRaises(InterruptedError), setup.interruption_cleanup():
                os.kill(os.getpid(), number)
            self.assertEqual(signal.getsignal(number), before)

    def test_hangup_after_replace_and_second_signal_cannot_abandon_rollback(
        self,
    ) -> None:
        prior = b"prior-image\n"
        self.target.write_bytes(prior)
        interrupted = False
        rollback_reloaded = False

        def run(arguments: list[str]) -> str:
            nonlocal interrupted, rollback_reloaded
            if arguments == [setup.NGINX, "-T"]:
                return self.target.read_text()
            if arguments == [setup.NGINX, "-t"]:
                if self.target.read_bytes() != prior:
                    interrupted = True
                    os.kill(os.getpid(), signal.SIGHUP)
                elif interrupted:
                    os.kill(os.getpid(), signal.SIGTERM)
                    self.assertIn(signal.SIGTERM, signal.sigpending())
            if arguments == [setup.SYSTEMCTL, "reload", "nginx"]:
                self.assertEqual(self.target.read_bytes(), prior)
                rollback_reloaded = True
            return ""

        with (
            self.assertRaises(InterruptedError),
            setup.interruption_cleanup(),
            patch.object(setup.os, "geteuid", return_value=0),
            patch.object(setup, "protected_directory"),
            patch.object(setup, "existing_configuration", return_value=prior),
            patch.object(setup, "command", side_effect=run),
        ):
            setup.install(self.settings)
        self.assertTrue(interrupted)
        self.assertTrue(rollback_reloaded)
        self.assertEqual(self.target.read_bytes(), prior)

    def binaries(self) -> tuple[str, str]:
        nginx, openssl = shutil.which("nginx"), shutil.which("openssl")
        if nginx is None or openssl is None:
            self.skipTest("actual Nginx checks require installed nginx and openssl")
        return nginx, openssl

    def config_file(self, body: str) -> Path:
        config = self.root / "nginx.conf"
        config.write_text(
            f"pid {self.root / 'nginx.pid'};\nerror_log stderr;\nevents {{}}\nhttp {{\naccess_log off;\n{body}\n}}\n"
        )
        return config

    def free_port(self) -> int:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            return listener.getsockname()[1]

    def test_actual_nginx_accepts_both_generated_phases(self) -> None:
        nginx, openssl = self.binaries()
        cert, key = self.root / "cert.pem", self.root / "key.pem"
        subprocess.run(
            [
                openssl,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=" + TEST_HOST,
                "-keyout",
                str(key),
                "-out",
                str(cert),
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        for phase in ("bootstrap", "https"):
            rendered = setup.Settings(TEST_HOST, phase).configuration()
            for port in (80, 443):
                # Never bind or reload the operator's live listeners.
                rendered = rendered.replace(
                    f"listen {port}", f"listen 127.0.0.1:{self.free_port()}"
                )
            rendered = rendered.replace(
                f"/etc/letsencrypt/live/{TEST_HOST}/fullchain.pem", str(cert)
            )
            rendered = rendered.replace(
                f"/etc/letsencrypt/live/{TEST_HOST}/privkey.pem", str(key)
            )
            config = self.config_file(rendered)
            setup.command([nginx, "-p", str(self.root), "-c", str(config), "-t"])

    def test_actual_nginx_conflict_warnings_are_failures_even_with_quoted_aliases(
        self,
    ) -> None:
        nginx, _ = self.binaries()
        for alias in ('"other#name"', '";"', '"{"', '"}"'):
            port = self.free_port()
            body = f"server {{ listen 127.0.0.1:{port}; server_name {alias} {TEST_HOST}; }}\nserver {{ listen 127.0.0.1:{port}; server_name {TEST_HOST}; }}"
            config = self.config_file(body)
            with self.assertRaisesRegex(RuntimeError, "conflicting server name"):
                setup.command([nginx, "-p", str(self.root), "-c", str(config), "-t"])

    def test_actual_nginx_keeps_foreign_default_for_unmatched_host(self) -> None:
        nginx, _ = self.binaries()
        port = self.free_port()
        (self.sites / "app.conf").write_text(
            f'server {{ listen 127.0.0.1:{port}; server_name app.example.com; access_log off; return 200 "foreign-default"; }}'
        )
        self.target.write_text(
            self.settings.configuration().replace(
                "listen 80;", f"listen 127.0.0.1:{port};"
            )
        )
        config = self.config_file(f"include {self.sites}/*;")
        process = subprocess.Popen(
            [
                nginx,
                "-p",
                str(self.root),
                "-c",
                str(config),
                "-g",
                "daemon off; master_process off;",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 10
            while True:
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                try:
                    connection.request(
                        "GET", "/", headers={"Host": "unmatched.example.com"}
                    )
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.read(), b"foreign-default")
                    break
                except ConnectionRefusedError:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        self.fail("owned fixture Nginx did not start")
                    time.sleep(0.05)
                finally:
                    connection.close()
        finally:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
