import json
from pathlib import Path
import subprocess
import unittest

from test_installer_review import dashboard


ROOT = Path(dashboard.__file__).resolve().parent


class WorkspaceModelTests(unittest.TestCase):
    def run_js(self, assertions):
        path = ROOT / 'ui' / 'workspace_studio.js'
        self.assertTrue(path.exists(), 'Phase 2 workspace controller is not implemented')
        code = "const assert=require('node:assert/strict');const W=require(" + json.dumps(str(path)) + ");\n" + assertions
        result = subprocess.run(['node', '-'], input=code, text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def run_dom(self, assertions):
        fragment=(ROOT/'ui/security_workspace.html').read_text(encoding='utf-8')
        fixture=json.dumps(str(ROOT/'tests/process_dom_fixture.js'))
        self.run_js("const f=require("+fixture+").createFixture("+json.dumps(fragment)+");\n"+"""
const el=id=>f.doc.getElementById(id), dialog=el('findingInspector');
dialog.open=false;dialog.showModal=()=>{dialog.open=true;};dialog.close=()=>{dialog.open=false;};
let status={check_id:'fixture',status:'cancelled',findings:Array.from({length:63},(_,i)=>({finding_id:'f'+i,title:'Finding '+i,score:i,severity:'Info',category:'Fixture',review_reasons:['Review only']}))};
const state={currentSecurityStatus:status,selectedSecurityFindingId:null};
const ledger={recorded:false,status:'Not recorded',entries:[]};
const bridge={doc:f.doc,win:f.win,readState:()=>state,coverage:()=>ledger,
 filteredFindings:s=>(s?.findings||[]).filter(row=>!el('securityFindingFilter').value||row.title.includes(el('securityFindingFilter').value)),
 renderFindingContent:(s,id)=>{el('securityFindingDetail').textContent=s.findings.find(row=>row.finding_id===id).title;},
 timeline:s=>(s?.findings||[]).map((row,i)=>({time:i?'2026-10-31':'',type:'Evidence',item:row.title,summary:'Fixture evidence',severity:'Info',findingId:row.finding_id,sortTime:i,missingTime:i===0}))};
W.init(bridge);
"""+assertions)

    def test_seven_views_have_one_active_panel_and_keyboard_tabs(self):
        self.run_dom("""
for(const view of ['run','findings','coverage','baselines','allowlist','timeline','reports']){
 W.selectSecurity(view);assert(!el('security-view-'+view).classList.contains('hidden'));
 assert.equal(el('security-tab-'+view).getAttribute('aria-selected'),'true');
}
f.key(el('security-tab-run'),'End');assert.equal(f.doc.activeElement.id,'security-tab-reports');
""")

    def test_findings_are_paged_and_pager_nodes_do_not_reset(self):
        self.run_dom("""
W.renderFindings(status);assert.equal(el('securityFindingsRows').querySelectorAll('tr').length,25);
const pager=el('securityFindingsPager'), next=pager.querySelector('[data-delta="1"]');next.click();
assert.match(pager.textContent,/page 2\/3/);assert.equal(pager.querySelector('[data-delta="1"]'),next);
el('securityFindingFilter').value='Finding 62';W.renderFindings(status);
assert.equal(el('securityFindingsRows').querySelectorAll('tr').length,1);assert.match(pager.textContent,/page 1\/1/);
""")

    def test_finding_drawer_selection_close_and_focus_restore(self):
        self.run_dom("""
W.renderFindings(status);el('security-tab-findings').focus();W.openFinding(status,'f2');
assert(dialog.open);assert.equal(state.selectedSecurityFindingId,'f2');assert.equal(el('securityFindingDetail').textContent,'Finding 2');
assert.equal(f.doc.activeElement.id,'closeFindingInspector');
el('closeFindingInspector').click();assert(!dialog.open);assert.equal(f.doc.activeElement.id,'security-tab-findings');
""")

    def test_new_security_record_does_not_keep_stale_drawer(self):
        self.run_dom("""
W.renderFindings(status);W.openFinding(status,'f1');
const other={check_id:'another',status:'completed',findings:[]};state.currentSecurityStatus=other;W.renderFindings(other);
assert(!dialog.open);assert.equal(state.selectedSecurityFindingId,null);
""")

    def test_coverage_view_preserves_unknown_and_sources(self):
        self.run_dom("""
W.renderCoverage(status);assert.match(el('securityCoverageEvidence').textContent,/Not recorded/);
assert.match(el('securityCoverageWarning').textContent,/not a clean result/);
ledger.recorded=true;ledger.status='partial';ledger.entries=[{category:'Fixture',status:'access_denied',scope:'Current user',sources:[{source:'Fixture source',status:'unavailable',reason_code:'policy',detail:'Unavailable fixture'}]}];
W.renderCoverage(status);assert.match(el('securityCoverageEvidence').textContent,/Access denied/);
assert.match(el('securityCoverageEvidence').textContent,/Unavailable fixture/);
""")

    def test_timeline_is_bounded_with_linked_findings_and_missing_times(self):
        self.run_dom("""
W.renderTimeline(status);assert.equal(el('securityTimelineRows').querySelectorAll('tr').length,25);
assert.match(el('securityTimelineSummary').textContent,/1 missing times/);
assert(el('securityTimelineRows').querySelector('[data-timeline-finding]'));
el('securityTimelineSearch').value='Finding 0';el('securityTimelineSearch').dispatchEvent(f.event('input'));
assert.match(el('securityTimelineRows').textContent,/Time unavailable/);
""")

    def test_unchanged_poll_keeps_expanded_coverage_and_timeline_nodes(self):
        self.run_dom("""
ledger.recorded=true;ledger.status='partial';ledger.entries=[{collector_id:'fixture',category:'Fixture',status:'partial',scope:'Current user',sources:[]}];
W.renderCoverage(status);const source=el('securityCoverageEvidence').querySelector('details');source.open=true;source.querySelector('summary').focus();
W.renderCoverage(JSON.parse(JSON.stringify(status)));
assert(el('securityCoverageEvidence').querySelector('details')===source);assert(source.open);assert(f.doc.activeElement===source.querySelector('summary'));
W.renderTimeline(status);const event=el('securityTimelineRows').querySelector('details');event.open=true;
W.renderTimeline(JSON.parse(JSON.stringify(status)));assert(el('securityTimelineRows').querySelector('details')===event);assert(event.open);
""")

    def test_changed_coverage_keeps_disclosure_and_its_summary_focus(self):
        self.run_dom("""
ledger.recorded=true;ledger.status='partial';ledger.entries=[{collector_id:'fixture',category:'Fixture',status:'partial',scope:'Current user',sources:[]}];
W.renderCoverage(status);const source=el('securityCoverageEvidence').querySelector('details');source.open=true;source.querySelector('summary').focus();
ledger.entries[0].sources.push({source:'Fixture second source',status:'unavailable',reason_code:'fixture'});W.renderCoverage(status);
const current=el('securityCoverageEvidence').querySelector('details');assert(current.open);assert.equal(f.doc.activeElement,current.querySelector('summary'));
""")

    def test_finding_close_restores_replaced_details_action(self):
        self.run_dom("""
W.renderFindings(status);W.selectSecurity('findings');
const button=el('securityFindingsRows').querySelector('button[data-security-finding]'), id=button.dataset.securityFinding;button.focus();
W.openFinding(status,id);W.renderFindings(status);el('closeFindingInspector').click();
assert.equal(f.doc.activeElement.dataset.securityFinding,id);assert.equal(f.doc.activeElement.tagName,'BUTTON');assert(f.doc.activeElement.isConnected);
""")

    def test_timeline_drawer_returns_to_originating_event_not_first_finding_link(self):
        self.run_dom("""
W.renderFindings(status);const events=['File Created','File Modified'].map((type,i)=>({time:'2026-10-31',type,item:'Fixture file',summary:'Before',findingId:'f1',sortTime:i}));
bridge.timeline=()=>events;W.selectSecurity('timeline');W.renderTimeline(status);
el('securityTimelineRows').querySelectorAll('[data-timeline-finding]')[1].focus();W.openFinding(status,'f1');
events[1].summary='Updated evidence';W.renderTimeline(status);W.closeFinding();
assert(f.doc.activeElement.closest('tr').textContent.includes('File Modified'));
assert.equal(el('security-tab-timeline').getAttribute('aria-selected'),'true');
""")

    def test_search_matches_literal_windows_paths_and_nested_values(self):
        self.run_js(r"""
const path=String.raw`C:\Windows\Installer\Fixture.msp`;
const rows=[{path,evidence:{commands:[String.raw`Z:\Fixture\App.exe --safe-fixture`]}}];
assert.equal(W.page(rows,{query:path}).total,1);
assert.equal(W.page(rows,{query:String.raw`Z:\Fixture\App.exe`}).total,1);
""")

    def test_terminal_steps_preserve_originals_without_waiting_or_invented_success(self):
        self.run_js("""
const steps=[{label:'Never started',status:'Waiting'},{label:'Interrupted',status:'running'},{label:'Optional',status:'Disabled'}];
const original=JSON.stringify(steps);const rows=W.stepRows(steps,{check_id:'fixture',status:'cancelled'});
assert.deepEqual(rows.map(r=>r.status),['Not run','Cancelled','Disabled']);
assert.equal(JSON.stringify(steps),original);
assert.equal(W.stepRows([],{check_id:'legacy',status:'completed'})[0].status,'Not recorded');
assert.equal(W.stepRows([],null)[0].status,'Not run');
""")

    def test_paging_is_bounded_numeric_and_clamped(self):
        self.run_js("""
const rows=Array.from({length:603},(_,i)=>({score:i,title:'Item '+i}));
let p=W.page(rows,{pageSize:100,page:99,sort:'score-desc'});assert.equal(p.page,7);assert.equal(p.rows.length,3);
p=W.page(rows,{pageSize:25,query:'Item 60',sort:'score-desc'});assert.equal(p.total,4);assert.equal(p.rows[0].score,602);
assert.equal(W.page(rows,{pageSize:1000}).rows.length,25);
""")

    def test_unknown_values_sort_last_not_as_zero(self):
        self.run_js("""
const rows=[{score:null,title:'Unknown'},{score:0,title:'Zero'},{score:1,title:'One'}];
assert.deepEqual(W.page(rows,{sort:'score-asc'}).rows.map(r=>r.title),['Zero','One','Unknown']);
assert.deepEqual(W.page(rows,{sort:'score-desc'}).rows.map(r=>r.title),['One','Zero','Unknown']);
""")

    def test_coverage_summary_never_grants_complete_from_zero_findings(self):
        self.run_js("""
assert.equal(W.coverageModel({check_id:'legacy',status:'completed',findings:[]},{recorded:false,status:'Not recorded'}).status,'Not recorded');
const model=W.coverageModel({check_id:'cancelled',status:'cancelled'},{recorded:true,status:'partial',entries:[]});
assert.equal(model.status,'partial');assert.equal(model.terminal,'cancelled');
""")

    def test_html_fields_are_escaped_and_unknown_is_not_clean(self):
        self.run_js("""
assert(!W.field('Path','<img src=x onerror=bad>').includes('<img'));
assert(W.field('Hash',null).includes('Unavailable'));assert(W.field('Count',0).includes('>0<'));
""")

    def test_source_statuses_remain_distinct(self):
        self.run_js("""
for(const state of ['complete','partial','access_denied','unavailable','disabled','cancelled','failed','not_recorded','not_run'])
 assert.equal(W.outcome(state).toLowerCase().replaceAll(' ','_'),state);
""")
