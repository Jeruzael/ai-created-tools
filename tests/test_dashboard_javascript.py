import re
import shutil
import subprocess
import unittest

from test_installer_review import dashboard


@unittest.skipUnless(shutil.which("node"), "Node.js is required for embedded JavaScript behavior tests.")
class ManifestJavascriptTests(unittest.TestCase):
    def run_javascript(self, names, assertions):
        html = dashboard.build_dashboard_html()
        javascript = html.split("<script>", 1)[1].split("</script>", 1)[0]
        functions = []
        for name in names:
            match = re.search(r"^(?:async )?function " + re.escape(name) + r"\([^)]*\) \{.*?^\}", javascript, re.MULTILINE | re.DOTALL)
            self.assertIsNotNone(match, name)
            functions.append(match.group())
        code = "const assert = require('node:assert/strict');\nconst asArray = value => Array.isArray(value) ? value : [];\n"
        code += "\n".join(functions) + "\n(async () => {\n" + assertions + "\n})().catch(error => { console.error(error); process.exitCode = 1; });"
        result = subprocess.run(["node", "-"], input=code, text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_snapshot_mismatch_is_an_issue_without_a_hash_error(self):
        self.run_javascript(["installerManifestIssues"], """
            const files = [
                {snapshot_matches: true, hash_error: null, backup_review: {eligible_for_manifest: true}},
                {snapshot_matches: false, hash_error: null, backup_review: {eligible_for_manifest: true}}
            ];
            assert.equal(installerManifestIssues({files}).length, 1);
        """)

    def test_invalidated_export_warns_and_requires_a_new_scan(self):
        self.run_javascript(["installerManifestReady", "installerManifestIssues", "exportInstallerBackupManifest"], """
            global.state = {installerCache: {
                review_id: 'displayed-review', summary: {backup_review_candidates: 1},
                files: [{path: 'fixture.msi', backup_review: {eligible_for_manifest: true}, checks: [], incomplete_checks: []}]
            }};
            const elements = {exportInstallerBackupManifest: {disabled: false, textContent: 'Export'}, refreshInstallerCache: {disabled: false}};
            global.$ = id => elements[id];
            const alerts = [];
            global.showActionAlert = (...args) => alerts.push(args);
            global.downloadSecurityBlob = () => {};
            global.renderInstallerCache = () => {};
            global.api = async (path, options) => {
                assert.equal(path, '/api/installer-cache/backup-review-manifest');
                assert.equal(JSON.parse(options.body).reviewId, 'displayed-review');
                return {candidate_count: 1, eligible_candidate_count: 0, files: [{path: 'fixture.msi', snapshot_matches: false,
                    hash_error: 'File changed', backup_review: {eligible_for_manifest: false, status: 'Manual investigation'}}]};
            };
            await exportInstallerBackupManifest();
            assert.equal(alerts.at(-1)[0], 'warning');
            assert.equal(state.installerCache.manifestRequiresRefresh, true);
            assert.equal(state.installerCache.files[0].backup_review.eligible_for_manifest, false);
            assert.equal(elements.exportInstallerBackupManifest.disabled, true);
            assert.equal(elements.refreshInstallerCache.disabled, false);
        """)

    def test_failed_rescan_disables_exports_from_the_old_scan(self):
        self.run_javascript(["installerManifestReady", "refreshInstallerCache"], """
            global.state = {installerCache: {files: [{needs_review: true, backup_review: {eligible_for_manifest: true}}]}};
            const elements = Object.fromEntries(['refreshInstallerCache', 'exportInstallerCandidates', 'exportInstallerBackupManifest',
                'installerCacheStatus', 'installerCacheRows', 'installerMissingRows'].map(id => [id, {disabled: false, textContent: '', innerHTML: ''}]));
            global.$ = id => elements[id];
            global.showActionAlert = () => {};
            let cleared = 0;
            global.renderInstallerCache = data => { assert.equal(data,null); cleared++; };
            global.api = async () => { throw new Error('Scan failed'); };
            await refreshInstallerCache();
            assert.equal(state.installerCache, null);
            assert.equal(elements.exportInstallerCandidates.disabled, true);
            assert.equal(elements.exportInstallerBackupManifest.disabled, true);
            assert.equal(elements.refreshInstallerCache.disabled, false);
            assert.equal(cleared,1);
        """)


if __name__ == "__main__":
    unittest.main()
