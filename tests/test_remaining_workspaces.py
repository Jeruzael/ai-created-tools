"""Milestone D assets and controller behavior; offline DOM ports, not browser QA."""
from html.parser import HTMLParser
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ("installer_workspace.html", "history_workspace.html", "help_workspace.html", "about_workspace.html")


class Markup(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.ids = {}
        self.duplicates = []
        self.icon_refs = []
        self.words = []
        self.feed(source)

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if "id" in attrs:
            if attrs["id"] in self.ids:
                self.duplicates.append(attrs["id"])
            self.ids[attrs["id"]] = (tag, attrs)
        if tag == "use":
            self.icon_refs.append(attrs.get("href", "").removeprefix("#"))

    def handle_data(self, value):
        self.words.append(value)

    @property
    def text(self):
        return " ".join(" ".join(self.words).split())


def fragments():
    result = []
    for name in ASSETS:
        path = ROOT / "ui" / name
        if not path.is_file():
            raise AssertionError("Remaining workspace asset is not implemented: " + name)
        result.append(path.read_text(encoding="utf-8"))
    return "\n".join(result).replace("__PROCESS_VERIFICATION_HELP__", (ROOT / "ui/process_verification_help.html").read_text(encoding="utf-8"))


class RemainingMarkupTests(unittest.TestCase):
    def test_all_legacy_ids_and_export_controls_survive_once(self):
        dom = Markup(fragments())
        for name in ("tab-installer", "refreshInstallerCache", "exportInstallerCandidates", "exportInstallerBackupManifest",
                     "installerCacheStatus", "installerCacheSummary", "installerCoverageDetails", "installerStatusFilter",
                     "installerConfidenceFilter", "installerTypeFilter", "installerEligibilityFilter", "installerIncompleteOnly",
                     "installerVisibleCount", "installerCacheRows", "installerMissingRows", "tab-history", "refreshHistory",
                     "historyRows", "tab-manual", "processVerificationHelp", "verification-panel", "tab-about", "versionInfo"):
            self.assertIn(name, dom.ids, name)
        self.assertFalse(dom.duplicates)
        for name in ("exportInstallerCandidates", "exportInstallerBackupManifest"):
            self.assertIn("disabled", dom.ids[name][1])

    def test_installer_tabs_have_complete_keyboard_aria_relationships(self):
        dom = Markup(fragments())
        for name in ("overview", "packages", "coverage", "missing", "guidance"):
            tab = dom.ids["installer-tab-" + name][1]
            self.assertEqual(tab["role"], "tab")
            panel = dom.ids[tab["aria-controls"]][1]
            self.assertEqual(panel["role"], "tabpanel")
            self.assertEqual(panel["aria-labelledby"], "installer-tab-" + name)
            self.assertEqual("hidden" in panel, name != "overview")

    def test_installer_safety_and_manifest_controls_keep_the_original_meaning(self):
        dom = Markup(fragments())
        for phrase in (
            "a probable-orphan result is not a safe-to-delete verdict.",
            "without launching it. Use it to create a review list, not to clean automatically.",
            "Keep direct references and installed product or patch matches.",
            "registration visibility can be limited.",
            "They can explain future repair, update, or uninstall failures.",
            "Use Windows Storage settings and Disk Cleanup first.",
            "Run this read-only cache review.",
            "Export review candidates if any are found.",
            "Review the ProductCode, PatchCode, target ProductCodes, applicability, confidence, and incomplete checks.",
            "before any manual removal.",
            "Confirm Windows Update, app updates, repair, modify, and uninstall operations still work.",
            "based only on size, date, or filename.",
        ):
            self.assertIn(phrase, dom.text)

    def test_all_legacy_manual_topics_and_sensitive_safety_copy_are_retained(self):
        source = fragments()
        dom = Markup(source)
        for heading in ("Purpose Of This Tool", "Recommended First Scan", "How To Use The Dashboard", "Scan Settings Explained",
                        "Scan Setting Examples And Use Cases", "Reparse Points, Junctions, And Symlinks", "Common Use Cases",
                        "What To Review First", "Important Do Rules", "Important Don't Rules", "Good Cleanup Candidates",
                        "Folders That Need Extra Care", "Recommended Cleanup Workflow", "Unity Project Notes", "Blender And 3D Notes",
                        "Developer Folder Notes", "Process Review Caution", "Report Privacy Reminder", "Final Safety Rule"):
            self.assertIn(heading, dom.text)
        for phrase in (
            "It does not delete, move, rename, compress, kill, quarantine, upload, or modify files or processes.",
            "The dashboard skips these by default to avoid scanning the same files twice, following loops, or showing misleading totals.",
            "Don't manually delete files inside", "Don't randomly delete AppData", "Don't randomly delete Unity Assets",
            "Don't share reports publicly without redacting private paths.",
            "Some can be regenerated, but do not delete source folders", "close Unity first",
            "These indicators are not a final malware or safety verdict.",
            "When unsure, do not delete it immediately. Back it up or move it to a temporary review folder first.",
        ):
            self.assertIn(phrase, dom.text)
        for category in ("Getting Started", "Disk Scanning", "Understanding Results", "Process Verification", "Security Check", "Installer Cache", "Safety"):
            self.assertIn(category, dom.text)
        self.assertIn("__PROCESS_VERIFICATION_HELP__", (ROOT / "ui/help_workspace.html").read_text(encoding="utf-8"))
        self.assertIn("Do not upload private company files", dom.text)
        self.assertIn('Get-FileHash "C:\\Path\\To\\File.exe" -Algorithm SHA256', dom.text)

    def test_about_keeps_private_local_readonly_and_raw_metadata_access(self):
        dom = Markup(fragments())
        self.assertIn("Windows Disk Usage Dashboard", dom.text)
        self.assertIn("This app runs locally on 127.0.0.1. It does not upload scan or process data.", dom.text)
        self.assertIn("It cannot prove that a program is safe or harmful.", dom.text)
        self.assertEqual(dom.ids["aboutTechnicalDetails"][0], "details")
        self.assertNotIn("open", dom.ids["aboutTechnicalDetails"][1])
        self.assertEqual(dom.ids["versionInfo"][0], "pre")

    def test_pagers_are_statically_allocated_and_every_icon_is_local(self):
        dom = Markup(fragments())
        for kind in ("installerFiles", "installerMissing", "history"):
            for suffix in ("PageSize", "PageInfo", "Previous", "Next"):
                self.assertIn(kind + suffix, dom.ids)
        sprite = Markup((ROOT / "ui/lucide-sprite.svg").read_text(encoding="utf-8"))
        for name in dom.icon_refs:
            self.assertIn(name, sprite.ids)


class RemainingControllerTests(unittest.TestCase):
    def run_js(self, assertions):
        path = ROOT / "ui/remaining_workspaces.js"
        self.assertTrue(path.is_file(), "RemainingWorkspace controller has not been implemented")
        setup = r"""
const assert = require('node:assert/strict');
const RemainingWorkspace = require(CONTROLLER);
const Workspace = require(WORKSPACE);
const {createFixture} = require(FIXTURE);
const f=createFixture(FRAGMENTS),doc=f.doc,el=id=>doc.getElementById(id);
doc.querySelectorAll('details').forEach(node=>node.open=node.hasAttribute('open'));
let source=Array.from({length:61},(_,i)=>({name:'package'+(i+1)+'.msi',path:'C:\\Windows\\Installer\\package'+(i+1)+'.msi',
    size_bytes:(i+1)*1000,modified_at:'2026-10-01',classification:'Unknown',confidence:'Unknown',needs_review:true,
    products:['Product '+(i+1)],publishers:['Publisher'],extension:'.msi',incomplete_checks:['metadata unavailable'],
    backup_review:{status:'Manual investigation',eligible_for_manifest:false}}));
let callbacks=0,bounded=[];
const bridge={doc,win:f.win,page:Workspace.page,renderInstallerFiles:()=>{
    callbacks++;bounded=RemainingWorkspace.pageInstallerFiles(source);
}};
RemainingWorkspace.init(bridge);
const change=(id,value,type='change')=>{el(id).value=value;el(id).dispatchEvent(f.event(type))};
const records=(length=61)=>Array.from({length},(_,i)=>({scan_id:'scan-'+(i+1),started_at:'2026-01-'+String(i%28+1).padStart(2,'0')+'T01:00:00Z',
    status:i%2?'cancelled':'completed',root:'C:\\Folder'+(i+1),total_size:(i+1)+' KB',files_scanned:i+1,skipped_count:i%5,report_path:'report.html'}));
const historyRows=()=>el('historyRows').querySelectorAll('tr[data-history-record]');
const missingRows=()=>el('installerMissingRows').querySelectorAll('tr[data-installer-missing]');
"""
        for key, value in {"CONTROLLER": str(path), "WORKSPACE": str(ROOT / "ui/workspace_studio.js"),
                           "FIXTURE": str(ROOT / "tests/process_dom_fixture.js"), "FRAGMENTS": fragments()}.items():
            setup = setup.replace(key, json.dumps(value))
        result = subprocess.run(["node", "-"], input=setup + "\n(async()=>{\n" + assertions + "\n})().catch(error=>{console.error(error);process.exitCode=1});",
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_installer_default_and_keyboard_tabs_hide_inactive_panels(self):
        self.run_js("""
assert.equal(el('installer-view-overview').hidden,false);assert.equal(el('installer-view-packages').hidden,true);
f.key(el('installer-tab-overview'),'ArrowRight');assert.equal(doc.activeElement,el('installer-tab-packages'));
assert.equal(el('installer-tab-packages').getAttribute('aria-selected'),'true');assert.equal(el('installer-tab-overview').tabIndex,-1);
f.key(el('installer-tab-packages'),'End');assert.equal(doc.activeElement,el('installer-tab-guidance'));
f.key(el('installer-tab-guidance'),'Home');assert.equal(doc.activeElement,el('installer-tab-overview'));
RemainingWorkspace.selectInstaller('missing');assert.equal(el('installer-view-missing').hidden,false);
RemainingWorkspace.selectInstaller('invalid');assert.equal(el('installer-view-overview').hidden,false);
""")

    def test_installer_rows_are_bounded_and_original_classification_objects_are_returned(self):
        self.run_js("""
const input=source.map(item=>Object.freeze(item));Object.freeze(input);
const rows=RemainingWorkspace.pageInstallerFiles(input);assert.equal(rows.length,25);assert.equal(rows[0],input[60]);
assert.equal(rows[0].backup_review.eligible_for_manifest,false);assert.equal(rows[0].classification,'Unknown');
assert.equal(el('installerFilesPrevious').disabled,true);assert.match(el('installerFilesPageInfo').textContent,/61/);
""")

    def test_installer_numeric_sort_and_search_go_through_real_workspace_page(self):
        self.run_js("""
source=[{name:'small',size_bytes:900,publishers:['Vendor']},{name:'large',size_bytes:10000,publishers:['Other']},{name:'missing',size_bytes:null}];
bounded=RemainingWorkspace.pageInstallerFiles(source);assert.deepEqual(bounded.map(row=>row.name),['large','small','missing']);
change('installerFilesSort','size_bytes-asc');assert.deepEqual(bounded.map(row=>row.name),['small','large','missing']);
change('installerFilesSearch','Vendor','input');assert.deepEqual(bounded.map(row=>row.name),['small']);assert.equal(callbacks,2);
""")

    def test_installer_page_size_and_pager_nodes_and_focus_are_stable(self):
        self.run_js("""
RemainingWorkspace.pageInstallerFiles(source);const next=el('installerFilesNext'),size=el('installerFilesPageSize'),info=el('installerFilesPageInfo');
next.focus();next.click();assert.equal(bounded.length,25);assert.equal(doc.activeElement,next);
assert.equal(el('installerFilesNext'),next);assert.equal(el('installerFilesPageInfo'),info);
change('installerFilesPageSize','50');assert.equal(bounded.length,50);assert.equal(el('installerFilesPageSize'),size);
next.click();assert.equal(bounded.length,11);assert.equal(next.disabled,true);assert.equal(callbacks,3);
change('installerFilesPageSize','100');assert.equal(bounded.length,61);
""")

    def test_installer_refresh_preserves_page_scroll_and_legacy_filter_change_resets(self):
        self.run_js("""
RemainingWorkspace.pageInstallerFiles(source);el('installerFilesNext').click();const before=bounded.map(row=>row.name);
el('installerFilesTableScroll').scrollTop=190;assert.deepEqual(RemainingWorkspace.pageInstallerFiles(source).map(row=>row.name),before);
assert.equal(el('installerFilesTableScroll').scrollTop,190);
el('installerStatusFilter').value='keep';RemainingWorkspace.pageInstallerFiles(source);assert.equal(el('installerFilesPrevious').disabled,true);
assert.equal(callbacks,1);
""")

    def test_installer_empty_result_is_not_rendered_or_reclassified_by_adapter(self):
        self.run_js("""
el('installerCacheRows').textContent='PARENT EVIDENCE';assert.deepEqual(RemainingWorkspace.pageInstallerFiles([]),[]);
assert.equal(el('installerCacheRows').textContent,'PARENT EVIDENCE');assert.match(el('installerFilesPageInfo').textContent,/0/);
""")

    def test_installer_summary_preserves_unknown_zero_and_secondary_evidence(self):
        self.run_js(r"""
RemainingWorkspace.renderInstallerSummary(null);assert.match(el('installerCacheSummary').textContent,/Not run/i);
assert.doesNotMatch(el('installerCacheSummary').textContent,/clean|safe to delete/i);
RemainingWorkspace.renderInstallerSummary({summary:{status:'Partial',cache_files:0,backup_review_candidates:0,missing_registered_files:null,
    registered_files:0,installed_product_matches:7,probable_orphans:2},coverage:{status:'partial'},errors:['Restricted metadata']});
assert.match(el('installerCacheSummary').textContent,/Partial/);assert.match(el('installerCacheSummary').textContent,/Not recorded/);
assert.match(el('installerAdditionalSummary').textContent,/Installed MSI Matches\s*7/);
assert.match(el('installerCoverageNotice').textContent,/partial|incomplete/i);assert.match(el('installerCoverageNotice').textContent,/1/);
""")

    def test_missing_files_use_bounded_escaped_native_contract_and_stable_controls(self):
        self.run_js("""
const missing=Array.from({length:61},(_,i)=>({path:'C:\\missing'+i+'.msi',products:['Product'],publishers:['Vendor'],recommendation:'Repair from vendor'}));
RemainingWorkspace.renderInstallerMissing(missing,{coverage:'partial'});assert.equal(missingRows().length,25);
const button=el('installerMissingNext');button.click();assert.equal(missingRows().length,25);assert.equal(el('installerMissingNext'),button);
change('installerMissingSearch','missing60','input');assert.equal(missingRows().length,1);assert.match(missingRows()[0].textContent,/Repair from vendor/);
assert.equal(el('installerMissingPrevious').disabled,true);assert.match(el('installerMissingStatus').textContent,/partial/i);
""")

    def test_missing_file_empty_and_unrecorded_and_filtered_are_distinct(self):
        self.run_js("""
RemainingWorkspace.renderInstallerMissing(null);assert.match(el('installerMissingRows').textContent,/no.*scan|not.*run/i);
RemainingWorkspace.renderInstallerMissing([]);assert.match(el('installerMissingRows').textContent,/reported/);
assert.match(el('installerMissingStatus').textContent,/unavailable|not recorded/i);
RemainingWorkspace.renderInstallerMissing([{path:'one'}]);change('installerMissingSearch','nothing','input');
assert.match(el('installerMissingRows').textContent,/match/);assert.doesNotMatch(el('installerMissingRows').textContent,/no.*scan/i);
""")

    def test_history_renders_real_summary_contract_with_cancelled_and_zero_values(self):
        self.run_js("""
RemainingWorkspace.renderHistory([{scan_id:'saved-1',started_at:'2026-01-01T00:00:00Z',status:'cancelled',root:'C:\\Data',total_size:'0 B',files_scanned:0,skipped_count:0}]);
const row=historyRows()[0];assert.equal(row.querySelector('button').dataset.scan,'saved-1');assert.match(row.textContent,/cancelled/);
assert.match(row.textContent,/0 B/);assert.equal(row.children[4].textContent,'0');assert.equal(row.children[5].textContent,'0');
assert.equal(Object.values(el('historyRows').listeners).flat().length,0);
""")

    def test_history_size_sort_converts_formatted_backend_units_without_mutation(self):
        self.run_js("""
const rows=[{scan_id:'a',total_size:'900 B'},{scan_id:'b',total_size:'1.00 GB'},{scan_id:'c',total_size:'10.00 KB'},
    {scan_id:'d',total_size:'Unavailable'},{scan_id:'e',total_size:'0 B'}].map(Object.freeze);Object.freeze(rows);
RemainingWorkspace.renderHistory(rows);change('historySort','size-desc');
assert.deepEqual(historyRows().map(row=>row.querySelector('button').dataset.scan),['b','c','a','e','d']);
assert.equal(rows[0].total_size,'900 B');change('historySort','size-asc');
assert.deepEqual(historyRows().map(row=>row.querySelector('button').dataset.scan),['e','a','c','b','d']);
""")

    def test_history_numeric_counts_sort_and_missing_values_stay_unknown(self):
        self.run_js("""
RemainingWorkspace.renderHistory([{scan_id:'a',files_scanned:9,skipped_count:2},{scan_id:'b',files_scanned:100,skipped_count:20},{scan_id:'c'}]);
change('historySort','files-desc');assert.deepEqual(historyRows().map(row=>row.querySelector('button').dataset.scan),['b','a','c']);
assert.match(historyRows()[2].textContent,/Not recorded/);change('historySort','skipped-asc');
assert.deepEqual(historyRows().map(row=>row.querySelector('button').dataset.scan),['a','b','c']);
""")

    def test_history_time_sort_handles_offsets_and_keeps_missing_time_last(self):
        self.run_js("""
RemainingWorkspace.renderHistory([{scan_id:'a',started_at:'2026-01-01T01:00:00+02:00'},
    {scan_id:'b',started_at:'2026-01-01T00:00:00Z'},{scan_id:'c',started_at:'invalid'}]);
assert.deepEqual(historyRows().map(row=>row.querySelector('button').dataset.scan),['b','a','c']);
""")

    def test_history_search_page_sizes_and_static_pager_nodes(self):
        self.run_js("""
RemainingWorkspace.renderHistory(records());assert.equal(historyRows().length,25);const next=el('historyNext');next.focus();next.click();
assert.equal(historyRows().length,25);assert.equal(doc.activeElement,next);assert.equal(el('historyNext'),next);
change('historyPageSize','100');assert.equal(historyRows().length,61);
change('historySearch','Folder61','input');assert.equal(historyRows().length,1);assert.equal(el('historyPrevious').disabled,true);
assert.equal(historyRows()[0].querySelector('button').dataset.scan,'scan-61');
""")

    def test_history_refresh_preserves_page_filter_and_scroll_and_clamps_shrinking_source(self):
        self.run_js("""
const data=records();RemainingWorkspace.renderHistory(data);el('historyNext').click();const first=historyRows()[0].textContent;
el('historyTableScroll').scrollTop=150;RemainingWorkspace.renderHistory([...data]);assert.equal(historyRows()[0].textContent,first);
assert.equal(el('historyTableScroll').scrollTop,150);RemainingWorkspace.renderHistory(data.slice(0,2));
assert.equal(historyRows().length,2);assert.equal(el('historyPrevious').disabled,true);
""")

    def test_history_loading_error_unloaded_empty_and_no_match_states_are_explicit(self):
        self.run_js("""
RemainingWorkspace.renderHistory(null);assert.match(el('historyRows').textContent,/not.*loaded/i);
RemainingWorkspace.renderHistory([]);assert.match(el('historyRows').textContent,/No scan history/);
RemainingWorkspace.renderHistory(records(1));RemainingWorkspace.setHistoryLoading(true);
assert.equal(el('historyTableScroll').getAttribute('aria-busy'),'true');assert.equal(historyRows().length,1);
RemainingWorkspace.setHistoryError(Error('Read denied'));assert.match(el('historyStatus').textContent,/Read denied/);
assert.match(el('historyStatus').textContent,/last|previous/i);assert.equal(historyRows().length,1);
change('historySearch','unknown','input');assert.match(el('historyRows').textContent,/match/);
assert.equal(el('historyTableScroll').getAttribute('aria-busy'),'false');
""")

    def test_history_and_missing_rows_escape_untrusted_paths_and_scan_ids(self):
        self.run_js("""
const hostile='<img src=x onerror=alert(1)>';RemainingWorkspace.renderHistory([{scan_id:hostile,root:hostile,status:hostile}]);
assert.equal(el('historyRows').querySelector('img'),null);assert.equal(historyRows()[0].querySelector('button').dataset.scan,hostile);
RemainingWorkspace.renderInstallerMissing([{path:hostile,products:[hostile],recommendation:hostile}]);
assert.equal(el('installerMissingRows').querySelector('img'),null);assert.match(el('installerMissingRows').textContent,/<img/);
""")

    def test_help_search_includes_collapsed_technical_guide_and_restores_disclosures(self):
        self.run_js("""
const topic=el('processVerificationHelp');topic.open=false;
change('helpSearch','Get-AuthenticodeSignature','input');assert.equal(topic.hidden,false);assert.equal(topic.open,true);
assert.equal(el('help-category-disk-scanning').hidden,true);assert.equal(el('helpNoResults').hidden,true);
change('helpSearch','','input');assert.equal(topic.open,false);assert.equal(el('help-category-disk-scanning').hidden,false);
""")

    def test_help_category_filter_and_no_results_are_accessible(self):
        self.run_js("""
change('helpCategory','safety');assert.equal(el('help-category-safety').hidden,false);assert.equal(el('help-category-installer').hidden,true);
change('helpSearch','impossible-marker','input');assert.equal(el('helpNoResults').hidden,false);
assert.match(el('helpResultsStatus').textContent,/0/);change('helpSearch','','input');assert.equal(el('helpNoResults').hidden,true);
""")

    def test_contextual_process_help_clears_obscuring_filters_and_focuses_existing_summary(self):
        self.run_js("""
change('helpCategory','installer');change('helpSearch','package','input');RemainingWorkspace.openProcessHelp();
assert.equal(el('helpCategory').value,'all');assert.equal(el('helpSearch').value,'');assert.equal(el('processVerificationHelp').hidden,false);
assert.equal(el('processVerificationHelp').open,true);assert.equal(doc.activeElement,el('processVerificationHelp').querySelector('summary'));
""")

    def test_about_human_versions_and_complete_technical_json_are_not_truncated(self):
        self.run_js("""
const version=Object.freeze({app_version:'1.29.0',documentation_version:'1.29',revision_notes:'Read only',affected_areas:['all']});
RemainingWorkspace.renderAbout(version);assert.equal(el('aboutAppVersion').textContent,'1.29.0');
assert.equal(el('aboutDocumentationVersion').textContent,'1.29');assert.deepEqual(JSON.parse(el('versionInfo').textContent),version);
RemainingWorkspace.renderAbout(null);assert.equal(el('aboutAppVersion').textContent,'Not recorded');
assert.equal(el('aboutDocumentationVersion').textContent,'Not recorded');assert.match(el('versionInfo').textContent,/not recorded/i);
""")

    def test_init_is_idempotent_and_legacy_control_handlers_remain_parent_owned(self):
        self.run_js("""
RemainingWorkspace.init(bridge);RemainingWorkspace.pageInstallerFiles(source);el('installerFilesNext').click();assert.equal(callbacks,1);
for(const id of ['refreshInstallerCache','exportInstallerCandidates','exportInstallerBackupManifest','installerStatusFilter',
    'installerConfidenceFilter','installerTypeFilter','installerEligibilityFilter','installerIncompleteOnly','refreshHistory','historyRows'])
    assert.equal(Object.values(el(id).listeners).flat().length,0,id);
""")


if __name__ == "__main__":
    unittest.main()
