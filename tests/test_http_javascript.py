import re
import argparse
import shutil
import subprocess
import unittest

from test_installer_review import dashboard


@unittest.skipUnless(shutil.which("node"), "Node.js is required for JavaScript validation.")
class HttpJavascriptTests(unittest.TestCase):
    def javascript(self):
        return dashboard.build_dashboard_html().split("<script>", 1)[1].split("</script>", 1)[0]

    def run_api(self, assertions):
        match = re.search(r"^async function api\([^\n]*\) \{.*?^\}", self.javascript(), re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match)
        code = "const assert = require('node:assert/strict'); let sessionTokenPromise = null;\n" + match.group()
        code += "\n(async () => {\n" + assertions + "\n})().catch(e => {console.error(e); process.exitCode = 1;});"
        result = subprocess.run(["node", "-"], input=code, text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_entire_dashboard_script_has_valid_syntax(self):
        result = subprocess.run(["node", "--check", "-"], input=self.javascript(), text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_legacy_report_embedded_scripts_have_valid_syntax(self):
        settings = dashboard.parse_scan_settings({})
        scanner = dashboard.DiskScanner(argparse.Namespace(**settings, quiet=True, status_seconds=1,
                                                           show_skipped_live=False))
        root = r"C:\controlled-fixture"
        node = {"name": "fixture", "path": root, "size": 0, "file_count": 0, "children": []}
        html = dashboard.build_html_report(root, node, scanner)
        scripts = re.findall(r"<script>(.*?)</script>", html, re.DOTALL)
        self.assertTrue(scripts, "Legacy report scripts must actually be inspected.")
        for script in scripts:
            result = subprocess.run(["node", "--check", "-"], input=script, text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_parallel_api_calls_share_one_bootstrap_and_force_local_transport(self):
        self.run_api("""
            const calls = [];
            let release;
            global.fetch = async (path, options) => {
                calls.push({path, options});
                if (path === '/api/session') return await new Promise(resolve => {release = resolve;});
                return {ok: true, json: async () => ({path})};
            };
            const first = api('/api/state', {mode: 'cors', redirect: 'follow', headers: {'X-CSRF-Token': 'wrong'}});
            const second = api('/api/history');
            assert.equal(calls.length, 1);
            assert.equal(calls[0].path, '/api/session');
            release({ok: true, json: async () => ({csrf_token: 'session-fixture'})});
            const results = await Promise.all([first, second]);
            assert.equal(results[0].path, '/api/state');
            assert.equal(results[1].path, '/api/history');
            assert.equal(calls.length, 3);
            for (const call of calls) {
                assert.equal(call.options.mode, 'same-origin');
                assert.equal(call.options.credentials, 'same-origin');
                assert.equal(call.options.redirect, 'error');
                assert.equal(call.options.cache, 'no-store');
            }
            for (const call of calls.slice(1)) assert.equal(call.options.headers['X-CSRF-Token'], 'session-fixture');
        """)

    def test_failed_bootstrap_can_recover_without_reusing_failed_promise(self):
        self.run_api("""
            let bootstraps = 0;
            global.fetch = async path => {
                if (path === '/api/session') {
                    bootstraps++;
                    if (bootstraps === 1) return {ok: false, json: async () => ({error: 'temporary failure'})};
                    return {ok: true, json: async () => ({csrf_token: 'fresh-session'})};
                }
                return {ok: true, json: async () => ({recovered: true})};
            };
            await assert.rejects(api('/api/state'), /Session unavailable/);
            assert.equal((await api('/api/state')).recovered, true);
            assert.equal(bootstraps, 2);
        """)

    def test_wrapper_refuses_nonlocal_urls_before_requesting_a_token(self):
        self.run_api("""
            global.fetch = async () => {throw new Error('must not fetch');};
            for (const path of ['https://attacker.example/api/state', '//attacker.example/api/state', '/other']) {
                await assert.rejects(api(path), /Invalid local API path/);
            }
        """)


if __name__ == "__main__":
    unittest.main()
