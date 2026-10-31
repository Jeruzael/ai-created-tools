import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

from test_security_coverage import dashboard


@unittest.skipUnless(shutil.which("node"), "Node.js is required for Security Check presentation tests.")
class SecurityCoverageJavascriptTests(unittest.TestCase):
    def run_js(self, names, assertions):
        javascript = dashboard.build_dashboard_html().split("<script>", 1)[1].split("</script>", 1)[0]
        functions = []
        for name in names:
            match = re.search(r"^(?:async )?function " + re.escape(name) + r"\([^)]*\) \{.*?^\}",
                              javascript, re.MULTILINE | re.DOTALL)
            self.assertIsNotNone(match, name)
            functions.append(match.group())
        code = """
const assert = require('node:assert/strict');
const elements = {};
const $ = id => elements[id] ??= {innerHTML: ''};
const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const asArray = value => Array.isArray(value) ? value : [];
const metric = (label, value) => `${label}: ${value}; `;
const uniqueCount = items => new Set(items.filter(Boolean)).size;
const state = {securityBaselines: []};
""" + ("const buildSecurityTimelineRows = () => [];\n" if "buildSecurityTimelineRows" not in names else "") + "const Workspace=require(" + json.dumps(str(Path(__file__).resolve().parents[1] / 'ui/workspace_studio.js')) + ");\n" + "\n".join(functions) + "\n" + assertions
        result = subprocess.run(["node", "-"], input=code, text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_historical_categories_do_not_infer_complete_from_empty_findings(self):
        self.run_js(["securityCoverageView", "renderSecurityCategoryBlocks"], """
renderSecurityCategoryBlocks({check_id:'legacy', status:'completed', summary:{collectors_connected:true}, findings:[]});
assert(elements.securityCategoryBlocks.innerHTML.includes('Not recorded'));
assert(!elements.securityCategoryBlocks.innerHTML.includes('No findings in this category for the current run.'));
""")

    def test_terminal_steps_in_reports_preserve_saved_evidence_without_waiting(self):
        self.run_js(['securityStepsHtml'], """
const record={check_id:'cancelled',status:'cancelled',steps:[{label:'First',status:'Complete'},{label:'Second',status:'Running'},{label:'Third',status:'Waiting'}]};
const before=JSON.stringify(record),html=securityStepsHtml(record);
assert(html.includes('<td>Cancelled</td>'));assert(html.includes('<td>Not run</td>'));
assert(!html.includes('<td>Waiting</td>'));assert(html.includes('Saved step status: Waiting'));
assert.equal(JSON.stringify(record),before);
""")

    def test_cancelled_timeline_never_claims_a_completed_inspection(self):
        self.run_js(['parseTimelineTime','addTimelineRow','timelineSummaryForFinding','buildSecurityTimelineRows'], """
const cancelled=buildSecurityTimelineRows({check_id:'cancelled',status:'cancelled',started_at:'2026-10-31T01:00:00Z',completed_at:'2026-10-31T01:01:00Z'});
assert(cancelled.some(row=>row.type==='Security Check Cancelled'));
assert(!cancelled.some(row=>row.type==='Security Check Completed'));
const active=buildSecurityTimelineRows({check_id:'running',status:'running',started_at:'2026-10-31T01:00:00Z'});
assert(!active.some(row=>/Completed|Finalized/.test(row.type)));
""")

    def test_summary_distinguishes_unknown_from_zero_and_compared_from_uncompared(self):
        self.run_js(['securityCoverageView','renderSecuritySummary'], """
renderSecuritySummary({}, {check_id:'legacy',status:'cancelled'});
assert(elements.securitySummary.innerHTML.includes('Findings: Not recorded'));
assert(elements.securitySummary.innerHTML.includes('Skipped Sources: Not recorded'));
renderSecuritySummary({findings_total:0,skipped_count:0}, {check_id:'fixture',status:'completed',findings:[],baseline_comparison:{new:0,changed:1,removed:2}});
assert(elements.securitySummary.innerHTML.includes('Findings: 0'));
assert(elements.securitySummary.innerHTML.includes('Baseline Changes: 3'));
""")

    def test_unchanged_polling_does_not_recreate_filter_options(self):
        self.run_js(['updateSelectOptions'], """
let writes=0;
elements.filter={value:'Fixture category',dataset:{},set innerHTML(value){writes++;}};
updateSelectOptions('filter',['Fixture category','Other'],'All categories');
updateSelectOptions('filter',['Other','Fixture category'],'All categories');
assert.equal(writes,1);assert.equal(elements.filter.value,'Fixture category');
updateSelectOptions('filter',['New category'],'All categories');
assert.equal(writes,2);assert.equal(elements.filter.value,'All categories');
""")

    def complete_ledger(self):
        coverage = dashboard.new_security_coverage("standard")
        for entry in coverage["collectors"]:
            if entry["selected"]:
                dashboard.update_security_coverage(coverage, entry["collector_id"], dashboard.SecurityCollection(
                    [], [], [dashboard.security_source_result(entry["collector_id"], "complete")]))
        return coverage

    def test_backend_rejection_wins_even_when_raw_entries_claim_complete(self):
        coverage = json.dumps(self.complete_ledger())
        self.run_js(["securityCoverageView", "securityCoverageHtml", "renderSecurityCategoryBlocks"], f"""
const record = {{check_id:'fixture',collector_coverage:{coverage},findings:[],
    summary:{{coverage_recorded:false,coverage_status:'not_recorded',collectors_connected:false}}}};
assert.equal(securityCoverageView(record).recorded, false);
assert.equal(securityCoverageView(record).status, 'Not recorded');
assert(securityCoverageHtml(record).includes('Not recorded'));
renderSecurityCategoryBlocks(record);
assert(!elements.securityCategoryBlocks.innerHTML.includes('No findings within the completed scope.'));
""")

    def test_raw_ledger_without_backend_approval_cannot_grant_complete(self):
        coverage = json.dumps(self.complete_ledger())
        self.run_js(["securityCoverageView"], f"""
const view = securityCoverageView({{check_id:'fixture',collector_coverage:{coverage},summary:{{collectors_connected:true}}}});
assert.equal(view.recorded, false);
assert.equal(view.status, 'Not recorded');
""")

    def test_malformed_rejected_source_rows_cannot_crash_report_coverage(self):
        coverage = self.complete_ledger()
        coverage["collectors"][0]["sources"] = [None]
        summary = dashboard.security_coverage_summary(coverage)
        self.run_js(["securityCoverageView", "securityCoverageHtml"], f"""
const html = securityCoverageHtml({{check_id:'fixture',collector_coverage:{json.dumps(coverage)},summary:{json.dumps(summary)}}});
assert(html.includes('Not recorded'));
""")

    def test_disabled_advanced_categories_are_labelled_disabled(self):
        record = dashboard.project_security_coverage({"check_id": "fixture", "mode": "standard", "options": {},
            "collector_coverage": dashboard.new_security_coverage("standard"), "findings": []})
        self.run_js(["securityCoverageView", "renderSecurityCategoryBlocks"], f"""
renderSecurityCategoryBlocks({json.dumps(record)});
const html = elements.securityCategoryBlocks.innerHTML;
assert(html.includes('disabled'));
assert(html.includes('Current-user Run/RunOnce'));
""")

    def test_completed_run_with_partial_coverage_has_a_visible_warning(self):
        coverage = self.complete_ledger()
        entry = coverage["collectors"][0]
        entry.update(status="partial", reason_code="access_denied")
        entry["sources"].append(dashboard.security_source_result("blocked_fixture", "access_denied", 0, "access_denied"))
        record = dashboard.project_security_coverage({"check_id": "fixture", "mode": "standard", "options": {},
            "status": "completed", "collector_coverage": coverage, "findings": []})
        self.run_js(["securityCoverageView", "renderSecuritySummary"], f"""
const record = {json.dumps(record)};
renderSecuritySummary({{overall_status:'Completed',collectors_connected:true}}, record);
assert(elements.securitySummary.innerHTML.includes('Collector Coverage: partial'));
assert(elements.securitySummary.innerHTML.includes('role="status"'));
assert(elements.securitySummary.innerHTML.includes('Collector coverage is incomplete'));
""")

    def test_all_html_reports_include_coverage_and_failure_details(self):
        coverage = dashboard.new_security_coverage("standard")
        entry = coverage["collectors"][8]
        entry.update(status="partial", reason_code="fixture_gap", sources=[{
            "source": "fixture<script>", "status": "access_denied", "reason_code": "access_denied",
            "detail": "FIXTURE_SIGNATURE_DENIED", "item_count": 0},
            dashboard.security_source_result("readable_fixture", "complete", 1)])
        record = dashboard.project_security_coverage({"check_id": "fixture", "mode": "standard", "options": {},
            "status": "completed", "collector_coverage": coverage, "findings": [],
            "skipped_items": [{"category": "File Verification", "status": "Unavailable", "message": "FIXTURE_SIGNATURE_DENIED"}]})
        names = ["securityCoverageView", "securityCoverageHtml", "securityReportShell", "securitySummaryHtml",
                 "securityFindingRows", "securitySkippedHtml", "securityBaselineComparisonHtml", "securityTimelineHtml",
                 "securityStepsHtml", "buildSecurityFullReportHtml", "buildSecurityFindingsReportHtml",
                 "verificationRelevantFinding", "buildSecurityVerificationReportHtml"]
        self.run_js(names, f"""
const record = {json.dumps(record)};
for (const builder of [buildSecurityFullReportHtml, buildSecurityFindingsReportHtml, buildSecurityVerificationReportHtml]) {{
    const html = builder(record);
    assert(html.includes('Collector Coverage'));
    assert(html.includes('FIXTURE_SIGNATURE_DENIED'));
    assert(html.includes('access_denied'));
    assert(!html.includes('fixture<script>'));
}}
""")


if __name__ == "__main__":
    unittest.main()
