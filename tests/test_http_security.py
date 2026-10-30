"""Real loopback HTTP requests; all application data is isolated in fixtures."""

import http.client
import io
import json
from email.message import Message
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest import mock
from http.server import ThreadingHTTPServer

from test_installer_review import dashboard


class HttpSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        cls.patches = [mock.patch.object(dashboard, "APP_DIR", root)]
        for name in ("RECORDS_DIR", "REPORTS_DIR", "SECURITY_RECORDS_DIR", "BASELINES_DIR"):
            cls.patches.append(mock.patch.object(dashboard, name, root / name))
        for name in ("VERSION_FILE", "ALLOWLIST_FILE"):
            cls.patches.append(mock.patch.object(dashboard, name, root / (name + ".json")))
        cls.patches.append(mock.patch.object(dashboard, "get_available_drives", return_value=[]))
        for patch in cls.patches:
            patch.start()
        with mock.patch.object(dashboard, "ensure_version_metadata", return_value={"app_version": dashboard.APP_VERSION}):
            cls.app = dashboard.DashboardApp()
        cls.state_patch = mock.patch.object(dashboard, "APP_STATE", cls.app)
        cls.state_patch.start()
        cls.server = dashboard.DashboardHTTPServer(("127.0.0.1", 0), dashboard.DashboardRequestHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.host = "127.0.0.1:" + str(cls.server.server_port)
        cls.origin = "http://" + cls.host

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.state_patch.stop()
        for patch in reversed(cls.patches):
            patch.stop()
        cls.temp.cleanup()

    def request(self, route="/api/scans/cancel", method="POST", body=b"{}", headers=None,
                extra_headers=(), declared_length=None, half_close=True):
        values = {"Host": self.host, "Origin": self.origin,
                  "X-CSRF-Token": getattr(self.app, "csrf_token", "unguarded-baseline"),
                  "Content-Type": "application/json"}
        if headers:
            values.update(headers)
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            connection.putrequest(method, route, skip_host=True)
            for name, value in values.items():
                if value is not None:
                    connection.putheader(name, value)
            connection.putheader("Content-Length", str(len(body) if declared_length is None else declared_length))
            for name, value in extra_headers:
                connection.putheader(name, value)
            connection.endheaders()
            if body:
                connection.send(body)
            # End the request explicitly: a truncated fixture cannot hang a baseline read.
            if half_close:
                connection.sock.shutdown(socket.SHUT_WR)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def assert_blocked(self, expected, **kwargs):
        with mock.patch.object(self.app, "cancel_scan", return_value={"cancelled": True}) as action:
            status, headers, body = self.request(**kwargs)
        self.assertEqual(status, expected, body)
        action.assert_not_called()
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.assertNotIn(getattr(self.app, "csrf_token", "unguarded-baseline").encode(), body)

    def test_valid_same_origin_action_and_nonbrowser_action(self):
        for origin in (self.origin, None):
            with self.subTest(origin=origin), mock.patch.object(self.app, "cancel_scan", return_value={"cancelled": True}) as action:
                status, _headers, body = self.request(headers={"Origin": origin})
                self.assertEqual(status, 200, body)
                self.assertTrue(json.loads(body)["cancelled"])
                action.assert_called_once_with()

    def test_session_bootstrap_is_private_and_session_bound(self):
        status, headers, body = self.request("/api/session", method="GET", headers={"X-CSRF-Token": None})
        self.assertEqual(status, 200, body)
        token = json.loads(body)["csrf_token"]
        self.assertGreaterEqual(len(token), 43)
        self.assertEqual(token, self.app.csrf_token)
        with mock.patch.object(dashboard, "ensure_version_metadata", return_value={}):
            self.assertNotEqual(token, dashboard.DashboardApp().csrf_token)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_missing_and_invalid_tokens_cannot_dispatch(self):
        for token in (None, "", "invalid", "x" * 43):
            with self.subTest(token=token):
                self.assert_blocked(403, headers={"X-CSRF-Token": token})

    def test_foreign_origins_and_ambiguous_origin_are_rejected(self):
        for origin in ("https://attacker.example", "null", self.origin + "/", "http://localhost:1"):
            with self.subTest(origin=origin):
                self.assert_blocked(403, headers={"Origin": origin})
        self.assert_blocked(403, extra_headers=(("Origin", self.origin),))

    def test_malicious_host_and_wrong_port_are_rejected(self):
        for host in ("attacker.example", "127.0.0.1", "127.0.0.1:1", "localhost.attacker.example:1",
                     "127.0.0.1.attacker.example", "127.0.0.1.:" + str(self.server.server_port),
                     "user@" + self.host, self.host + ",attacker.example", None):
            with self.subTest(host=host):
                self.assert_blocked(403, headers={"Host": host})
        self.assert_blocked(403, extra_headers=(("Host", self.host),))

    def test_explicit_localhost_alias_with_matching_origin_is_valid(self):
        alias = "localhost:" + str(self.server.server_port)
        with mock.patch.object(self.app, "cancel_scan", return_value={}) as action:
            status, _headers, body = self.request(headers={"Host": alias, "Origin": "http://" + alias})
        self.assertEqual(status, 200, body)
        action.assert_called_once()

    def test_fetch_metadata_blocks_cross_site_even_without_origin(self):
        for site in ("cross-site", "same-site"):
            with self.subTest(site=site):
                self.assert_blocked(403, headers={"Origin": None, "Sec-Fetch-Site": site})

    def test_simple_text_plain_post_never_reaches_an_action(self):
        self.assert_blocked(403, headers={"Origin": "https://attacker.example", "Content-Type": "text/plain"})
        for content_type in (None, "text/plain", "application/x-www-form-urlencoded", "application/jsonp"):
            with self.subTest(content_type=content_type):
                self.assert_blocked(415, headers={"Content-Type": content_type})

    def test_invalid_reparse_flag_returns_400_without_starting_work(self):
        invalid = ("false", "true", 0, 1, 0.0, 1.0, "", None, {}, {"value": False}, [], [False])
        with mock.patch.object(self.app, "_start_worker") as launch:
            for value in invalid:
                with self.subTest(value=value):
                    payload = {"root": self.temp.name, "acknowledgeSafety": True, "includeReparse": value}
                    status, _headers, body = self.request("/api/scans", body=json.dumps(payload).encode())
                    self.assertEqual(status, 400, body[:300])
                    self.assertIn("includeReparse", json.loads(body)["error"])
            launch.assert_not_called()
        self.assertIsNone(self.app.active_scan)
        self.assertIsNone(self.app._operation)

    def test_invalid_security_flags_return_400_without_starting_work(self):
        invalid = ("false", "true", 0, 1, 0.0, 1.0, "", None, {}, {"value": False}, [], [False])
        with mock.patch.object(self.app, "_start_worker") as launch:
            for flag in ("registryBackup", "wmiCheck", "eventLogCorrelation", "sysmonCorrelation"):
                for value in invalid:
                    with self.subTest(flag=flag, value=value):
                        payload = {"acknowledgeSafety": True, "mode": "advanced", flag: value}
                        status, _headers, body = self.request("/api/security-checks", body=json.dumps(payload).encode())
                        self.assertEqual(status, 400, body[:300])
                        self.assertIn(flag, json.loads(body)["error"])
            launch.assert_not_called()
        self.assertIsNone(self.app.active_security_check)
        self.assertIsNone(self.app._operation)

    def test_malformed_json_shape_utf8_constants_and_duplicate_keys(self):
        for body in (b"{", b"[]", b"null", b'"string"', b'{"value":NaN}', b'{"x":1,"x":2}', b"\xff",
                     b'{"value":1e400}', b'{"nested":{"value":-1e400}}'):
            with self.subTest(body=body):
                self.assert_blocked(400, body=body)

    def test_invalid_framing_truncated_and_oversized_bodies(self):
        for length in ("-1", "invalid", "2, 2"):
            with self.subTest(length=length):
                self.assert_blocked(400, declared_length=length)
        self.assert_blocked(400, extra_headers=(("Content-Length", "2"),))
        self.assert_blocked(400, extra_headers=(("Transfer-Encoding", "chunked"),))
        self.assert_blocked(400, declared_length=10)
        self.assert_blocked(413, declared_length=4 * 1024 * 1024 + 1)

    def test_private_reads_and_resource_intensive_get_require_token(self):
        routes = ("/api/state", "/api/history", "/api/scans/active", "/api/security-checks/active",
                  "/api/security-baselines", "/api/security-allowlist", "/api/installer-cache", "/api/processes")
        with mock.patch.object(self.app, "installer_cache_review") as installer, \
                mock.patch.object(dashboard, "get_process_snapshot") as processes:
            for route in routes:
                with self.subTest(route=route):
                    status, _headers, body = self.request(route, method="GET", headers={"X-CSRF-Token": None})
                    self.assertEqual(status, 403, body)
            installer.assert_not_called()
            processes.assert_not_called()

    def test_all_sensitive_post_routes_reject_before_dispatch(self):
        routes = {"/api/scans": "start_scan", "/api/security-checks": "start_security_check",
                  "/api/security-checks/cancel": "cancel_security_check",
                  "/api/security-baselines": "create_security_baseline",
                  "/api/security-allowlist": "add_security_allowlist_entry",
                  "/api/security-allowlist/remove": "remove_security_allowlist_entry",
                  "/api/security-allowlist/import": "import_security_allowlist",
                  "/api/installer-cache/backup-review-manifest": "installer_backup_review_manifest",
                  "/api/shutdown": "request_shutdown"}
        for route, name in routes.items():
            with self.subTest(route=route), mock.patch.object(self.app, name, return_value={}) as action, \
                    mock.patch.object(self.server, "shutdown"):
                status, _headers, body = self.request(route, headers={"X-CSRF-Token": None})
                self.assertEqual(status, 403, body)
                action.assert_not_called()

    def test_foreign_origin_cannot_read_html_or_bootstrap(self):
        for route in ("/", "/api/session"):
            with self.subTest(route=route):
                status, _headers, body = self.request(route, method="GET", headers={"Origin": "https://attacker.example"})
                self.assertEqual(status, 403, body)
                self.assertNotIn(b"csrf_token", body)

    def test_valid_private_state_and_html_have_no_embedded_token(self):
        status, _headers, body = self.request("/api/state", method="GET")
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["version"]["app_version"], dashboard.APP_VERSION)
        status, _headers, body = self.request("/", method="GET", headers={"X-CSRF-Token": None})
        self.assertEqual(status, 200, body)
        self.assertNotIn(self.app.csrf_token.encode(), body)

    def test_absolute_form_and_preflight_are_not_action_routes(self):
        self.assert_blocked(403, route="http://attacker.example/api/scans/cancel")
        self.assert_blocked(403, method="OPTIONS", headers={"Origin": "https://attacker.example"})

    def test_record_path_builders_reject_traversal_and_absolute_identifiers(self):
        for builder in (dashboard.scan_record_path, dashboard.security_check_record_path, dashboard.security_baseline_path):
            for value in ("../outside", r"C:\audit-fixture\outside", "", "not-a-record", "a" * 31, "a" * 33):
                with self.subTest(builder=builder.__name__, value=value), self.assertRaises(ValueError):
                    builder(value)
            path = builder("a" * 32)
            self.assertEqual(path.name, "a" * 32 + ".json")


class HttpServerResourceTests(unittest.TestCase):
    def setUp(self):
        self.server = dashboard.DashboardHTTPServer(("127.0.0.1", 0), dashboard.DashboardRequestHandler)
        self.server._request_slots = threading.BoundedSemaphore(1)
        self.addCleanup(self.server.server_close)

    def test_admission_limit_rejects_without_starting_another_thread(self):
        self.assertTrue(self.server._request_slots.acquire(blocking=False))
        request = mock.Mock()
        request.recv.return_value = b""
        with mock.patch.object(ThreadingHTTPServer, "process_request") as start, \
                mock.patch.object(self.server, "shutdown_request") as close:
            self.server.process_request(request, ("127.0.0.1", 1))
        start.assert_not_called()
        close.assert_called_once_with(request)
        self.assertIn(b"503 Service Unavailable", request.sendall.call_args.args[0])
        self.server._request_slots.release()

    def test_thread_launch_failure_releases_request_slot(self):
        with mock.patch.object(ThreadingHTTPServer, "process_request", side_effect=RuntimeError("launch failed")):
            with self.assertRaisesRegex(RuntimeError, "launch failed"):
                self.server.process_request(mock.Mock(), ("127.0.0.1", 1))
        self.assertTrue(self.server._request_slots.acquire(blocking=False))
        self.server._request_slots.release()

    def test_request_failure_releases_slot_and_handlers_are_not_daemons(self):
        self.assertFalse(self.server.daemon_threads)
        self.assertTrue(self.server.block_on_close)
        self.assertTrue(self.server._request_slots.acquire(blocking=False))
        with mock.patch.object(ThreadingHTTPServer, "process_request_thread", side_effect=RuntimeError("handler failed")):
            with self.assertRaisesRegex(RuntimeError, "handler failed"):
                self.server.process_request_thread(mock.Mock(), ("127.0.0.1", 1))
        self.assertTrue(self.server._request_slots.acquire(blocking=False))
        self.server._request_slots.release()

    def test_rejection_drains_unread_input_after_fin_before_socket_close(self):
        events = []
        request = mock.Mock()
        request.shutdown.side_effect = lambda _how: events.append("fin")
        request.recv.side_effect = lambda _size: events.append("drain") or b""
        with mock.patch.object(self.server, "shutdown_request", side_effect=lambda _request: events.append("close")):
            self.server._reject_request(request, 409, "Conflict", "Server closing.")
        self.assertEqual(events, ["fin", "drain", "close"])
        self.assertIn(b"409 Conflict", request.sendall.call_args.args[0])

    def test_rejection_drain_has_a_fixed_byte_budget(self):
        request = mock.Mock()
        request.recv.return_value = b"x" * 4096
        with mock.patch.object(dashboard.time, "monotonic", return_value=100.0), \
                mock.patch.object(self.server, "shutdown_request") as close:
            self.server._reject_request(request, 503, "Service Unavailable", "Busy.")
        self.assertEqual(request.recv.call_count, 16)
        self.assertTrue(all(call.args[0] <= 4096 for call in request.recv.call_args_list))
        close.assert_called_once_with(request)

    def test_rejection_drain_uses_an_absolute_deadline(self):
        clock = [100.0]
        request = mock.Mock()

        def receive(_size):
            clock[0] += 1.0
            return b"dripping input"

        request.recv.side_effect = receive
        with mock.patch.object(dashboard.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(self.server, "shutdown_request") as close:
            self.server._reject_request(request, 409, "Conflict", "Server closing.")
        request.recv.assert_called_once()
        close.assert_called_once_with(request)

    def test_rejection_drain_error_still_closes_the_socket(self):
        request = mock.Mock()
        request.recv.side_effect = TimeoutError("fixture receive timeout")
        with mock.patch.object(self.server, "shutdown_request") as close:
            self.server._reject_request(request, 409, "Conflict", "Server closing.")
        request.recv.assert_called_once()
        close.assert_called_once_with(request)


class ManualDeadlineTimer:
    def __init__(self, interval, callback):
        self.interval = interval
        self.callback = callback
        self.cancelled = False
        self.joined = False
        self.daemon = False

    def start(self):
        pass

    def cancel(self):
        self.cancelled = True

    def join(self):
        self.joined = True

    def fire(self):
        # Model a callback already awake when cancellation wins the dispatch race.
        self.callback()


class HttpAbsoluteDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.clock = 100.0
        self.timers = []
        self.server = dashboard.DashboardHTTPServer(("127.0.0.1", 0), dashboard.DashboardRequestHandler)
        self.addCleanup(self.server.server_close)
        self.patches = [
            mock.patch.object(dashboard.time, "monotonic", side_effect=lambda: self.clock),
            mock.patch.object(dashboard.threading, "Timer", side_effect=self.timer),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.connection = mock.Mock()
        self.connection.makefile.return_value = io.BytesIO()
        self.connection.detach.return_value = -1
        self.handler = dashboard.DashboardRequestHandler.__new__(dashboard.DashboardRequestHandler)
        self.handler.request = self.connection
        self.handler.server = self.server
        self.handler.setup()
        self.addCleanup(self.handler.finish)

    def timer(self, interval, callback):
        timer = ManualDeadlineTimer(interval, callback)
        self.timers.append(timer)
        return timer

    def dispatch(self):
        dispatch = getattr(self.handler, "_begin_dispatch", None)
        self.assertTrue(callable(dispatch), "Dispatch must enforce and disarm the absolute request deadline")
        dispatch()

    def test_timer_closes_a_header_reader_at_the_absolute_deadline(self):
        self.assertEqual(len(self.timers), 1, "A total deadline must start before header parsing")
        self.clock += dashboard.HTTP_REQUEST_TIMEOUT_SECONDS
        self.timers[0].fire()
        self.connection.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        with self.assertRaises(dashboard.HttpRequestError) as error:
            self.dispatch()
        self.assertEqual(error.exception.status, 408)

    def test_body_and_headers_share_one_budget_even_if_timer_callback_is_delayed(self):
        headers = Message()
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = "2"
        self.handler.headers = headers

        def body_read(_length):
            self.clock += dashboard.HTTP_REQUEST_TIMEOUT_SECONDS + 1
            return b"{}"

        self.handler.rfile = mock.Mock(read=body_read)
        self.assertEqual(dashboard.read_request_json(self.handler), {})
        with self.assertRaises(dashboard.HttpRequestError) as error:
            self.dispatch()
        self.assertEqual(error.exception.status, 408)
        self.assertEqual(len(self.timers), 1, "Body parsing must not restart the deadline")

    def test_timer_is_cancelled_and_joined_before_a_legitimate_action(self):
        self.dispatch()
        self.assertTrue(self.timers[0].cancelled)
        self.assertTrue(self.timers[0].joined)
        self.clock += dashboard.HTTP_REQUEST_TIMEOUT_SECONDS + 1
        self.timers[0].fire()
        self.connection.shutdown.assert_not_called()

    def test_finish_disarms_and_joins_timer_after_a_rejected_request(self):
        self.assertEqual(len(self.timers), 1)
        self.handler.finish()
        self.assertTrue(self.timers[0].cancelled)
        self.assertTrue(self.timers[0].joined)
        self.timers[0].fire()
        self.connection.shutdown.assert_not_called()

    def test_deadline_expiry_and_dispatch_race_cannot_admit_a_late_action(self):
        self.assertEqual(len(self.timers), 1)
        self.clock += dashboard.HTTP_REQUEST_TIMEOUT_SECONDS
        barrier = threading.Barrier(2)
        outcomes = []

        def expired():
            barrier.wait(5)
            self.timers[0].fire()

        thread = threading.Thread(target=expired)
        thread.start()
        try:
            barrier.wait(5)
            try:
                self.dispatch()
                outcomes.append("dispatched")
            except dashboard.HttpRequestError as error:
                outcomes.append(error.status)
        finally:
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(outcomes, [408])


class HttpGuardedServerFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="dashboard-http-shutdown-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        patch = mock.patch.multiple(
            dashboard, APP_DIR=root, RECORDS_DIR=root / "scans", REPORTS_DIR=root / "reports",
            SECURITY_RECORDS_DIR=root / "checks", BASELINES_DIR=root / "baselines",
            ALLOWLIST_FILE=root / "allowlist.json", VERSION_FILE=root / "version.json",
        )
        patch.start()
        self.addCleanup(patch.stop)
        self.app = dashboard.DashboardApp(initialize_storage=False)
        state = mock.patch.object(dashboard, "APP_STATE", self.app)
        state.start()
        self.addCleanup(state.stop)
        self.server = dashboard.DashboardHTTPServer(("127.0.0.1", 0), dashboard.DashboardRequestHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.host = "127.0.0.1:" + str(self.server.server_port)
        self.origin = "http://" + self.host

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)
        self.assertFalse(self.thread.is_alive())

    def request(self, *args, **kwargs):
        return HttpSecurityTests.request(self, *args, half_close=False, **kwargs)

    def background_request(self, *args, **kwargs):
        results, errors = [], []

        def request():
            try:
                results.append(self.request(*args, **kwargs))
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=request)
        thread.start()
        return thread, results, errors

    def join_request(self, task):
        thread, results, errors = task
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        return results[0]


class HttpShutdownAdmissionTests(HttpGuardedServerFixture):
    def test_shutdown_rejects_while_process_get_is_still_in_flight(self):
        entered, release = threading.Event(), threading.Event()

        def processes():
            entered.set()
            if not release.wait(5):
                raise RuntimeError("fixture process GET was not released")
            return []

        with mock.patch.object(dashboard, "get_process_snapshot", side_effect=processes), \
                mock.patch.object(self.app, "request_shutdown", wraps=self.app.request_shutdown) as shutdown:
            task = self.background_request("/api/processes", method="GET", body=b"")
            try:
                self.assertTrue(entered.wait(5))
                status, _headers, _body = self.request("/api/shutdown")
                self.assertEqual(status, 409)
                shutdown.assert_not_called()
            finally:
                release.set()
                self.assertEqual(self.join_request(task)[0], 200)

    def test_shutdown_rejects_while_a_short_allowlist_write_is_in_flight(self):
        entered, release = threading.Event(), threading.Event()
        original = dashboard.atomic_write_json

        def write(path, payload):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("fixture persistence was not released")
            return original(path, payload)

        body = json.dumps({"acknowledgeImport": True, "allowlist": {"schema_version": "security-allowlist-v1", "entries": []}}).encode()
        with mock.patch.object(dashboard, "atomic_write_json", side_effect=write), \
                mock.patch.object(self.app, "request_shutdown", wraps=self.app.request_shutdown) as shutdown:
            task = self.background_request("/api/security-allowlist/import", body=body)
            try:
                self.assertTrue(entered.wait(5))
                self.assertEqual(self.request("/api/shutdown")[0], 409)
                shutdown.assert_not_called()
            finally:
                release.set()
                self.assertEqual(self.join_request(task)[0], 200)
        self.assertEqual(json.loads(dashboard.ALLOWLIST_FILE.read_text())["entries"], [])

    def test_shutdown_rejects_another_handler_still_reading_headers(self):
        accepted = threading.Event()
        setup = dashboard.DashboardRequestHandler.setup

        def observe(handler):
            setup(handler)
            accepted.set()

        with mock.patch.object(dashboard.DashboardRequestHandler, "setup", observe), \
                mock.patch.object(self.app, "request_shutdown", wraps=self.app.request_shutdown) as shutdown:
            connection = socket.create_connection(("127.0.0.1", self.server.server_port), timeout=5)
            try:
                self.assertTrue(accepted.wait(5))
                connection.sendall(b"GET / HTTP/1.1\r\n")
                self.assertEqual(self.request("/api/shutdown")[0], 409)
                shutdown.assert_not_called()
            finally:
                connection.close()

    def test_closing_is_visible_before_app_admission_and_rolls_back_on_rejection(self):
        entered, release = threading.Event(), threading.Event()

        def reject():
            entered.set()
            if not release.wait(5):
                raise RuntimeError("fixture shutdown admission was not released")
            raise RuntimeError("An application job is still active")

        with mock.patch.object(self.app, "request_shutdown", side_effect=reject):
            task = self.background_request("/api/shutdown")
            try:
                self.assertTrue(entered.wait(5))
                self.assertEqual(self.request("/api/session", method="GET", body=b"")[0], 409)
            finally:
                release.set()
                self.assertEqual(self.join_request(task)[0], 409)
        self.assertEqual(self.request("/api/session", method="GET", body=b"")[0], 200)

    def test_accepted_shutdown_closes_admission_and_drains_only_its_handler(self):
        stopping, allow_stop = threading.Event(), threading.Event()
        draining, release_handler, closed, joining = (threading.Event() for _ in range(4))
        original_shutdown = self.server.shutdown

        def stop():
            stopping.set()
            if not allow_stop.wait(5):
                raise RuntimeError("fixture server stop was not released")
            original_shutdown()
            draining.set()
            if not release_handler.wait(5):
                raise RuntimeError("fixture shutdown handler was not released")

        with mock.patch.object(self.server, "shutdown", side_effect=stop):
            task = self.background_request("/api/shutdown")
            closer = None
            try:
                self.assertTrue(stopping.wait(5))
                self.assertEqual(self.request("/api/session", method="GET", body=b"")[0], 409)
                allow_stop.set()
                self.assertTrue(draining.wait(5))
                original_join = self.server._threads.join

                def join_handlers():
                    joining.set()
                    original_join()

                def close():
                    self.server.server_close()
                    closed.set()

                with mock.patch.object(self.server._threads, "join", side_effect=join_handlers):
                    closer = threading.Thread(target=close)
                    closer.start()
                    self.assertTrue(joining.wait(5))
                    self.assertFalse(closed.is_set())
                    release_handler.set()
                    closer.join(5)
                    self.assertFalse(closer.is_alive())
            finally:
                allow_stop.set()
                release_handler.set()
                self.assertEqual(self.join_request(task)[0], 200)
                if closer:
                    closer.join(5)
        self.assertTrue(closed.is_set())


class HttpDeadlineSocketTests(HttpGuardedServerFixture):
    def setUp(self):
        super().setUp()
        self.clock = 0.0
        self.timers = []
        self.created, self.released = threading.Event(), threading.Event()
        original_release = self.server._release_request

        def timer(interval, callback):
            value = ManualDeadlineTimer(interval, callback)
            self.timers.append(value)
            self.created.set()
            return value

        def release(request):
            original_release(request)
            self.released.set()

        for patch in (
            mock.patch.object(dashboard.threading, "Timer", side_effect=timer),
            mock.patch.object(dashboard.time, "monotonic", side_effect=lambda: self.clock),
            mock.patch.object(self.server, "_release_request", side_effect=release),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def assert_connection_expired(self, connection):
        try:
            self.assertEqual(connection.recv(1), b"")
        except (ConnectionResetError, ConnectionAbortedError):
            pass
        self.assertTrue(self.released.wait(5))
        self.assertTrue(self.timers[0].cancelled)
        self.assertTrue(self.timers[0].joined)
        self.assertEqual(self.server._inflight_requests, set())

    def test_absolute_timer_interrupts_incomplete_headers_and_releases_admission(self):
        connection = socket.create_connection(("127.0.0.1", self.server.server_port), timeout=5)
        try:
            self.assertTrue(self.created.wait(5))
            connection.sendall(f"GET /api/session HTTP/1.1\r\nHost: {self.host}\r\nX-Drip: ".encode())
            self.clock = dashboard.HTTP_REQUEST_TIMEOUT_SECONDS + 1
            self.timers[0].fire()
            self.assert_connection_expired(connection)
        finally:
            connection.close()
        self.assertEqual(self.request("/api/session", method="GET", body=b"")[0], 200)

    def test_absolute_timer_interrupts_incomplete_body_without_dispatch(self):
        reading = threading.Event()
        original = dashboard.read_request_json

        def read(handler):
            reading.set()
            return original(handler)

        with mock.patch.object(dashboard, "read_request_json", side_effect=read), \
                mock.patch.object(self.app, "cancel_scan", return_value={}) as action:
            connection = socket.create_connection(("127.0.0.1", self.server.server_port), timeout=5)
            try:
                connection.sendall(
                    f"POST /api/scans/cancel HTTP/1.1\r\nHost: {self.host}\r\nOrigin: {self.origin}\r\n"
                    f"X-CSRF-Token: {self.app.csrf_token}\r\nContent-Type: application/json\r\n"
                    "Content-Length: 20\r\n\r\n{".encode()
                )
                self.assertTrue(reading.wait(5))
                self.clock = dashboard.HTTP_REQUEST_TIMEOUT_SECONDS + 1
                self.timers[0].fire()
                self.assert_connection_expired(connection)
            finally:
                connection.close()
        action.assert_not_called()

    def test_late_timer_callback_does_not_interrupt_an_admitted_persistence_write(self):
        writing, release = threading.Event(), threading.Event()
        original = dashboard.atomic_write_json

        def write(path, payload):
            writing.set()
            if not release.wait(5):
                raise RuntimeError("fixture admitted write was not released")
            return original(path, payload)

        body = json.dumps({"acknowledgeImport": True, "allowlist": {"schema_version": "security-allowlist-v1", "entries": []}}).encode()
        with mock.patch.object(dashboard, "atomic_write_json", side_effect=write):
            task = self.background_request("/api/security-allowlist/import", body=body)
            try:
                self.assertTrue(writing.wait(5))
                self.assertTrue(self.timers[0].cancelled)
                self.assertTrue(self.timers[0].joined)
                self.clock = dashboard.HTTP_REQUEST_TIMEOUT_SECONDS + 1
                self.timers[0].fire()
            finally:
                release.set()
                self.assertEqual(self.join_request(task)[0], 200)
        self.assertEqual(json.loads(dashboard.ALLOWLIST_FILE.read_text())["entries"], [])


if __name__ == "__main__":
    unittest.main()
