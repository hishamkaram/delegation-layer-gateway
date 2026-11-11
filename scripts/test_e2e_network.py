"""Fixture authority wiring; explicit nonlocal IPs mock only the I/O boundary."""

from contextlib import ExitStack
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import e2e_local


class NetworkBindingTests(unittest.TestCase):
    def harness(self, directory, document=b'{"keys":[]}'):
        base = Path(directory)
        jwks = base / "jwks.json"
        jwks.write_bytes(document)
        harness = object.__new__(e2e_local.Harness)
        harness.base = base
        harness.home = base / "home"
        harness.args = SimpleNamespace(gateway=base / "gateway")
        harness.env = {}
        harness.admin_socket = base / "admin.sock"
        harness.fixture_allowed_ips = ()
        harness.summary = {"stages": []}
        harness.directory = mock.Mock(side_effect=lambda name: base / name)
        harness.material = {
            "jwks_file": str(jwks),
            "ca_file": str(base / "ca.pem"),
            "token_file": str(base / "token.json"),
            "tls": {"certificate": "server.pem", "private_key": "server.key"},
            "device_ca": {"certificate": "device.pem", "private_key": "device.key"},
        }
        harness.helper = mock.Mock(return_value=harness.material)
        harness.command = mock.Mock(return_value={"gateway_id": "gateway-id"})
        harness.input_file = mock.Mock(return_value=base / "config.json")
        harness.start_gateway = mock.Mock()
        harness.check_auth = mock.Mock()
        harness.admin = mock.Mock(return_value={"principal_id": "principal-id"})
        harness.last_mcp_started = 0
        harness.responses = []
        return harness

    def boundaries(self, stack):
        server = stack.enter_context(
            mock.patch.object(e2e_local.http.server, "HTTPServer")
        )
        server.return_value.server_port = 19001
        ports = stack.enter_context(mock.patch.object(e2e_local, "free_port"))
        ports.side_effect = [19002, 19003]
        tls = stack.enter_context(mock.patch.object(e2e_local.ssl, "SSLContext"))
        thread = stack.enter_context(mock.patch.object(e2e_local.threading, "Thread"))
        return server, ports, tls, thread

    def test_invalid_ip_fails_before_resources_helpers_or_children(self):
        for host in (
            "localhost",
            "::1",
            "::ffff:127.0.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "169.254.1.1",
            "255.255.255.255",
            "127.000.0.1",
            "192.0.2.1:443",
            "",
            None,
            2130706433,
        ):
            with self.subTest(host=host), tempfile.TemporaryDirectory() as directory:
                harness = self.harness(directory)
                with ExitStack() as stack:
                    boundaries = self.boundaries(stack)
                    with self.assertRaises(e2e_local.ProofFailure):
                        harness.start_network(listen_ip=host)
                    for boundary in boundaries:
                        boundary.assert_not_called()
                for boundary in (
                    harness.directory,
                    harness.helper,
                    harness.command,
                    harness.input_file,
                    harness.start_gateway,
                    harness.check_auth,
                    harness.admin,
                ):
                    boundary.assert_not_called()
                self.assertEqual(harness.fixture_allowed_ips, ())

    def test_exact_explicit_ip_controls_every_authority_and_helper_allowlist(self):
        for host in ("192.0.2.10", "127.0.0.2"):
            with self.subTest(host=host), tempfile.TemporaryDirectory() as directory:
                harness = self.harness(directory)
                with ExitStack() as stack:
                    server, ports, _, _ = self.boundaries(stack)
                    harness.start_network(listen_ip=host)
                self.assertEqual(server.call_args.args[0], (host, 0))
                self.assertEqual(
                    ports.call_args_list, [mock.call(host), mock.call(host)]
                )
                self.assertEqual(harness.fixture_allowed_ips, (host,))
                self.assertEqual(harness.public, f"https://{host}:19002")
                self.assertEqual(
                    harness.gateway_config["public_address"], f"{host}:19002"
                )
                self.assertEqual(
                    harness.gateway_config["device_address"], f"{host}:19003"
                )
                self.assertEqual(
                    harness.gateway_config["identity"],
                    {
                        "issuer": f"https://{host}:19001/",
                        "audience": f"https://{host}:19002/mcp",
                        "jwks_url": f"https://{host}:19001/jwks",
                    },
                )
                harness.helper.assert_called_once_with(
                    "material",
                    {
                        "directory": str(Path(directory) / "tls"),
                        "issuer": f"https://{host}:19001/",
                        "audience": f"https://{host}:19002/mcp",
                        "allowed_ips": [host],
                    },
                )
                self.assert_mcp_payload(harness, [host])

    def test_bind_failure_is_reported_without_fallback_or_child_start(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            harness = self.harness(directory)
            server, ports, tls, thread = self.boundaries(stack)
            server.side_effect = OSError("requested fixture address unavailable")
            with self.assertRaisesRegex(
                OSError, "requested fixture address unavailable"
            ):
                harness.start_network(listen_ip="192.0.2.10")
            self.assertEqual(server.call_count, 1)
            self.assertEqual(server.call_args.args[0], ("192.0.2.10", 0))
            for boundary in (ports, tls, thread, harness.helper, harness.start_gateway):
                boundary.assert_not_called()

    def assert_mcp_payload(self, harness, allowed_ips):
        harness.helper.reset_mock()
        harness.helper.return_value = {"structuredContent": {"data": {"ok": True}}}
        self.assertEqual(harness.mcp("inventory", {"device": "one"}), {"ok": True})
        expected = {
            "endpoint": harness.public + "/mcp",
            "ca_file": harness.material["ca_file"],
            "token_file": harness.material["token_file"],
            "tool": "inventory",
            "arguments": {"device": "one"},
        }
        if allowed_ips:
            expected["allowed_ips"] = allowed_ips
        harness.helper.assert_called_once_with("mcp", expected)

    def test_default_loopback_keeps_historical_helper_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            harness = self.harness(directory)
            with ExitStack() as stack:
                server, ports, _, _ = self.boundaries(stack)
                harness.start_network()
            self.assertEqual(server.call_args.args[0], ("127.0.0.1", 0))
            self.assertEqual(ports.call_args_list, [mock.call("127.0.0.1")] * 2)
            self.assertEqual(harness.fixture_allowed_ips, ())
            self.assertNotIn("allowed_ips", harness.helper.call_args.args[1])
            self.assertEqual(harness.public, "https://127.0.0.1:19002")
            self.assert_mcp_payload(harness, None)
            # Existing unit fixtures construct Harness without __init__.
            del harness.fixture_allowed_ips
            harness.last_mcp_started = 0
            self.assert_mcp_payload(harness, None)

    def test_harness_handlers_keep_independent_documents_before_serving(self):
        handlers = []
        documents = [b'{"keys":["first"]}', b'{"keys":["second"]}']
        for document in documents:
            with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                harness = self.harness(directory, document)
                server, _, _, thread = self.boundaries(stack)
                thread.return_value.start.side_effect = lambda: self.assertEqual(
                    server.call_args.args[1].document, document
                )
                harness.start_network()
                handlers.append(server.call_args.args[1])
        self.assertIsNot(handlers[0], handlers[1])
        self.assertEqual([handler.document for handler in handlers], documents)
        self.assertEqual(e2e_local.JWKSHandler.document, b"")

    def test_free_port_binds_only_the_requested_address(self):
        for host in ("127.0.0.1", "192.0.2.10"):
            with (
                self.subTest(host=host),
                mock.patch.object(e2e_local.socket, "socket") as factory,
            ):
                listener = factory.return_value.__enter__.return_value
                listener.getsockname.return_value = (host, 19005)
                port = (
                    e2e_local.free_port()
                    if host == "127.0.0.1"
                    else e2e_local.free_port(host)
                )
                self.assertEqual(port, 19005)
                listener.bind.assert_called_once_with((host, 0))


if __name__ == "__main__":
    unittest.main()
