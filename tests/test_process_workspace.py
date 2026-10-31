"""Bounded process sidecar tests, using its own fragment and an offline Node DOM port."""
from html.parser import HTMLParser
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Fragment(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.ids = {}
        self.duplicates = []
        self.icon_refs = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "use" and attrs.get("href", "").startswith("#"):
            self.icon_refs.append(attrs["href"][1:])
        if "id" in attrs:
            if attrs["id"] in self.ids:
                self.duplicates.append(attrs["id"])
            self.ids[attrs["id"]] = (tag, attrs)


class ProcessMarkupTests(unittest.TestCase):
    def source(self):
        path = ROOT / "ui/process_workspace.html"
        self.assertTrue(path.is_file(), "Process workspace fragment is not implemented")
        return path.read_text(encoding="utf-8")

    def test_fragment_preserves_bridge_ids_without_duplicate_process_tree(self):
        source = self.source()
        dom = Fragment(source)
        for name in ("processFilter", "processPublisherFilter", "processGroupBy", "processReviewFilter",
                     "needsReviewOnly", "refreshProcesses", "downloadProcessReport", "downloadVerificationReport",
                     "processRows", "processSummary", "processDetail"):
            self.assertIn(name, dom.ids)
        self.assertFalse(dom.duplicates)
        self.assertNotIn("processGroupTree", dom.ids)
        self.assertIn("data-open-process-help", source)

    def test_drawer_and_tabs_expose_accessible_relationships(self):
        dom = Fragment(self.source())
        drawer = dom.ids["processDrawer"][1]
        self.assertEqual(drawer["role"], "dialog")
        self.assertEqual(drawer["aria-modal"], "true")
        self.assertIn("hidden", drawer)
        self.assertIn(drawer["aria-labelledby"], dom.ids)
        for suffix in ("Overview", "Signature", "Technical"):
            tab = dom.ids["processTab" + suffix][1]
            self.assertEqual(tab["role"], "tab")
            panel = dom.ids[tab["aria-controls"]][1]
            self.assertEqual(panel["role"], "tabpanel")
            self.assertEqual(panel["aria-labelledby"], "processTab" + suffix)

    def test_all_fragment_icons_resolve_to_local_assets(self):
        dom = Fragment(self.source())
        local = Fragment((ROOT / "ui/lucide-sprite.svg").read_text(encoding="utf-8"))
        available = set(dom.ids) | set(local.ids)
        for reference in dom.icon_refs:
            self.assertIn(reference, available, "Unresolved icon: " + reference)


class ProcessWorkspaceTests(unittest.TestCase):
    def run_js(self, assertions):
        script = ROOT / "ui/process_workspace.js"
        fragment = ROOT / "ui/process_workspace.html"
        self.assertTrue(script.is_file() and fragment.is_file(), "Process sidecar is not implemented")
        setup = r"""
const assert = require('node:assert/strict');
const ProcessWorkspace = require(SCRIPT);
const {createFixture} = require(FIXTURE);
const f = createFixture(FRAGMENT), doc = f.doc, win = f.win;
const el = id => doc.getElementById(id);
const sample = (pid, bytes = pid * 1024, extra = {}) => ({pid, name: 'app' + pid + '.exe',
    friendly_name: 'App ' + pid, executable_path: 'C:\\Programs\\app' + pid + '.exe', parent_pid: 0,
    publisher: 'Publisher ' + (pid % 3), memory_bytes: bytes, memory: bytes + ' B',
    risk_indicators: [], review_reasons: [], ...extra});
let snapshot = Array.from({length: 61}, (_, index) => sample(index + 1));
let calls = [], notifications = [], copied = [], groupCalls = [];
let apiImpl = async url => ({process: sample(Number(url.split('/').pop()), 1, {
    signature: {status:'Valid', publisher:'Example signer', error:null}, sha256:'a'.repeat(64),
    command_line:'app.exe ' + 'long-argument '.repeat(80), collected_at:'2026-01-01T00:00:00Z'})});
const publisherLabel = p => p.publisher || p.company_name || 'Uncategorized / publisher unavailable';
const needsReview = p => !!p.needs_review || (p.review_reasons || []).length > 0;
const reviewReasons = p => p.review_reasons || [];
function visibleProcesses() {
    const query = el('processFilter').value.trim().toLowerCase();
    return snapshot.filter(p => !query || [p.friendly_name,p.name,p.pid,p.publisher,p.executable_path].join(' ').toLowerCase().includes(query))
        .filter(p => !el('processPublisherFilter').value || publisherLabel(p) === el('processPublisherFilter').value)
        .filter(p => !(el('needsReviewOnly').checked || el('processGroupBy').value === 'needsReview') || needsReview(p))
        .filter(p => !el('processReviewFilter').value || reviewReasons(p).includes(el('processReviewFilter').value))
        .filter(p => el('processGroupBy').value !== 'uncategorized' || !p.publisher);
}
function groupProcesses(rows, mode) {
    groupCalls.push(mode);
    const map = new Map();
    for (const p of rows) {
        const key = mode === 'memory' ? (p.memory_bytes >= 10000 ? 'High memory' : 'Low memory') :
            mode === 'needsReview' ? (reviewReasons(p)[0] || 'Needs review') : publisherLabel(p);
        if (!map.has(key)) map.set(key, {name:key,totalMemory:0,processes:[]});
        const group = map.get(key); group.processes.push(p); group.totalMemory += p.memory_bytes || 0;
    }
    return [...map.values()].sort((a,b) => b.totalMemory-a.totalMemory).map(g =>
        ({...g,processes:[...g.processes].sort((a,b)=>b.memory_bytes-a.memory_bytes)}));
}
const bridge = {doc,win,readState:()=>({processes:snapshot}),api:url=>{calls.push(url);return apiImpl(url)},
    visibleProcesses,groupProcesses,publisherLabel,needsReview,reviewReasons,formatBytes:b=>b+' B',
    notify:(...args)=>notifications.push(args),copyText:async text=>{copied.push(text)}};
ProcessWorkspace.init(bridge); ProcessWorkspace.render();
const rows = () => el('processRows').querySelectorAll('tr[data-pid]');
const pids = () => rows().map(row=>Number(row.dataset.pid));
const change = (id, value) => {el(id).value=value;el(id).dispatchEvent(f.event('change'));};
const sort = key => doc.querySelector('[data-process-sort="'+key+'"]').click();
const deferred = () => {let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no});return {promise,resolve,reject}};
const flush = async () => {for(let i=0;i<8;i++) await Promise.resolve()};
"""
        setup = setup.replace("SCRIPT", json.dumps(str(script))).replace("FIXTURE", json.dumps(str(ROOT / "tests/process_dom_fixture.js"))).replace("FRAGMENT", json.dumps(fragment.read_text(encoding="utf-8")))
        result = subprocess.run(["node", "-"], input=setup + "\n(async()=>{\n" + assertions + "\n})().catch(error=>{console.error(error);process.exitCode=1});",
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_default_table_is_bounded_with_seven_columns_and_snapshot_summary(self):
        self.run_js("""
assert.equal(rows().length,25);assert.equal(rows()[0].children.filter(x=>x.tagName==='TD').length,7);
assert.match(el('processSummary').textContent,/61/);assert.match(el('processSummary').textContent,/1936384 B/);
assert.equal(el('processDrawer').hidden,true);assert.equal(calls.length,0);
assert.equal(el('processGroupBy').value,'none');
""")

    def test_pagination_sizes_and_last_page_are_bounded_for_500_processes(self):
        self.run_js("""
snapshot=Array.from({length:501},(_,i)=>sample(i+1));ProcessWorkspace.render();
change('processPageSize','100');assert.equal(rows().length,100);
for(let i=0;i<5;i++)el('processNext').click();assert.equal(rows().length,1);
assert.equal(el('processNext').disabled,true);assert.match(el('processPageInfo').textContent,/501/);
el('processPrevious').click();assert.equal(rows().length,100);
change('processPageSize','50');assert.equal(rows().length,50);
""")

    def test_memory_sort_is_numeric_and_missing_measurements_remain_last(self):
        self.run_js("""
snapshot=[sample(1,900),sample(2,10000),sample(3,null),sample(4,0)];ProcessWorkspace.render();
sort('memory');assert.deepEqual(pids(),[2,1,4,3]);sort('memory');assert.deepEqual(pids(),[4,1,2,3]);
assert.equal(doc.querySelector('[data-process-sort="memory"]').closest('th').getAttribute('aria-sort'),'ascending');
""")

    def test_pid_sort_is_numeric_and_text_sort_is_stable(self):
        self.run_js("""
snapshot=[sample(10,10,{friendly_name:'Same'}),sample(2,2,{friendly_name:'Same'}),sample(1,1,{friendly_name:'Alpha'})];
ProcessWorkspace.render();sort('pid');assert.deepEqual(pids(),[1,2,10]);
sort('program');assert.deepEqual(pids(),[1,10,2]);
""")

    def test_compact_sort_selector_uses_same_numeric_sort_and_synchronizes_headers(self):
        self.run_js("""
snapshot=[sample(1,900),sample(2,10000),sample(3,0)];ProcessWorkspace.render();
change('processSort','memory-desc');assert.deepEqual(pids(),[2,1,3]);
assert.equal(doc.querySelector('[data-process-sort="memory"]').closest('th').getAttribute('aria-sort'),'descending');
sort('memory');assert.equal(el('processSort').value,'memory-asc');assert.deepEqual(pids(),[3,1,2]);
change('processSort','bogus');assert.deepEqual(pids(),[3,1,2]);assert.equal(el('processSort').value,'memory-asc');
""")

    def test_search_filter_is_delegated_and_resets_page_only_on_filter_change(self):
        self.run_js("""
el('processNext').click();const before=pids();el('processTableScroll').scrollTop=180;
ProcessWorkspace.render();assert.deepEqual(pids(),before);assert.equal(el('processTableScroll').scrollTop,180);
el('processFilter').value='app61.exe';ProcessWorkspace.render();assert.deepEqual(pids(),[61]);
assert.equal(el('processPrevious').disabled,true);assert.match(el('processSummary').textContent,/61/);
el('processFilter').value='';ProcessWorkspace.render();assert.equal(rows().length,25);
""")

    def test_publisher_reason_and_review_filters_are_consumed_not_reimplemented(self):
        self.run_js("""
snapshot=[sample(1),sample(2,2,{needs_review:true,review_reasons:['Path review']})];
el('processPublisherFilter').value='Publisher 2';ProcessWorkspace.render();assert.deepEqual(pids(),[2]);
el('processPublisherFilter').value='';el('processReviewFilter').value='Path review';ProcessWorkspace.render();assert.deepEqual(pids(),[2]);
el('processReviewFilter').value='';el('needsReviewOnly').checked=true;ProcessWorkspace.render();assert.deepEqual(pids(),[2]);
""")

    def test_grouping_uses_authoritative_helper_and_compact_table_headers(self):
        self.run_js("""
change('processGroupBy','memory');ProcessWorkspace.render();assert.equal(groupCalls.at(-1),'memory');
assert.ok(el('processRows').querySelectorAll('[data-process-group]').length>0);assert.equal(rows().length,25);
assert.equal(el('processRows').querySelector('[data-process-group]').querySelector('th').getAttribute('colspan'),'7');
change('processGroupBy','uncategorized');snapshot=[sample(1,1,{publisher:''}),sample(2)];ProcessWorkspace.render();
assert.equal(groupCalls.at(-1),'publisher');assert.deepEqual(pids(),[1]);
""")

    def test_group_helpers_cannot_override_selected_numeric_sort_within_groups(self):
        self.run_js("""
snapshot=[sample(1,1,{publisher:'One'}),sample(2,20,{publisher:'One'}),sample(3,3,{publisher:'One'})];
el('processGroupBy').value='publisher';ProcessWorkspace.render();sort('memory');sort('memory');assert.deepEqual(pids(),[1,3,2]);
""")

    def test_open_fetches_only_supplied_api_and_selects_row_without_resetting_table(self):
        self.run_js("""
el('processNext').click();const before=pids();el('processTableScroll').scrollTop=225;
const opener=rows()[0].querySelector('button');opener.focus();await ProcessWorkspace.open(opener.dataset.pid,opener);
assert.equal(calls[0],'/api/processes/'+opener.dataset.pid);assert.equal(el('processDrawer').hidden,false);
assert.equal(doc.activeElement,el('processDrawerClose'));assert.equal(rows()[0].classList.contains('selected'),true);
assert.equal(rows()[0].querySelector('button').getAttribute('aria-expanded'),'true');
assert.deepEqual(pids(),before);assert.equal(el('processTableScroll').scrollTop,225);assert.equal(notifications.length,0);
""")

    def test_cached_details_and_same_pid_inflight_requests_are_reused(self):
        self.run_js("""
const request=deferred();apiImpl=()=>request.promise;
const first=ProcessWorkspace.open(1),second=ProcessWorkspace.open(1);assert.equal(calls.length,1);
request.resolve({process:sample(1)});await Promise.all([first,second]);
ProcessWorkspace.close();await ProcessWorkspace.open(1);ProcessWorkspace.render();assert.equal(calls.length,1);
""")

    def test_refresh_when_closed_invalidates_cache_without_prefetch(self):
        self.run_js("""
await ProcessWorkspace.open(1);ProcessWorkspace.close();await ProcessWorkspace.onSnapshot();assert.equal(calls.length,1);
await ProcessWorkspace.open(1);assert.equal(calls.length,2);
""")

    def test_newer_selection_wins_over_slow_older_success(self):
        self.run_js("""
const a=deferred(),b=deferred();apiImpl=url=>url.endsWith('/1')?a.promise:b.promise;
const first=ProcessWorkspace.open(1),second=ProcessWorkspace.open(2);
b.resolve({process:sample(2)});await second;a.resolve({process:sample(1)});await first;
assert.match(el('processDrawerTitle').textContent,/App 2/);assert.doesNotMatch(el('processDetailOverview').textContent,/App 1/);
""")

    def test_newer_selection_wins_over_slow_older_failure(self):
        self.run_js("""
const a=deferred();apiImpl=url=>url.endsWith('/1')?a.promise:Promise.resolve({process:sample(2)});
const first=ProcessWorkspace.open(1);await ProcessWorkspace.open(2);a.reject(Error('Old request denied'));await first;
assert.match(el('processDrawerTitle').textContent,/App 2/);assert.doesNotMatch(el('processDetailStatus').textContent,/Old request/);
""")

    def test_close_and_hide_invalidate_async_display(self):
        self.run_js("""
const a=deferred();apiImpl=()=>a.promise;const opening=ProcessWorkspace.open(1);
ProcessWorkspace.hide();a.resolve({process:sample(1)});await opening;
assert.equal(el('processDrawer').hidden,true);assert.equal(el('processDrawerBackdrop').hidden,true);
assert.equal(el('fixtureOpener').inert,false);
""")

    def test_refresh_invalidates_details_but_preserves_page_filter_sort_and_drawer_tab(self):
        self.run_js("""
sort('memory');el('processNext').click();const before=pids();await ProcessWorkspace.open(before[0]);
el('processTabTechnical').click();el('processDetail').scrollTop=120;el('processTableScroll').scrollTop=240;
ProcessWorkspace.render();assert.equal(calls.length,1);
await ProcessWorkspace.onSnapshot();await flush();assert.equal(calls.length,2);
assert.deepEqual(pids(),before);assert.equal(el('processTableScroll').scrollTop,240);
assert.equal(el('processTabTechnical').getAttribute('aria-selected'),'true');assert.equal(el('processDetail').scrollTop,120);
""")

    def test_refresh_discards_old_pending_response_even_for_same_pid(self):
        self.run_js("""
const old=deferred(),fresh=deferred();apiImpl=()=>calls.length===1?old.promise:fresh.promise;
const opening=ProcessWorkspace.open(1);const refreshing=ProcessWorkspace.onSnapshot();
fresh.resolve({process:sample(1,200,{friendly_name:'Fresh instance'})});await refreshing;await flush();
old.resolve({process:sample(1,100,{friendly_name:'Stale instance'})});await opening;
assert.match(el('processDrawerTitle').textContent,/Fresh instance/);
""")

    def test_terminated_selection_has_explicit_nonverdict_state_and_no_refetch(self):
        self.run_js("""
await ProcessWorkspace.open(1);snapshot=snapshot.filter(p=>p.pid!==1);await ProcessWorkspace.onSnapshot();
assert.equal(calls.length,1);assert.equal(el('processDrawer').hidden,false);
assert.match(el('processDetailStatus').textContent,/no longer|terminated|not.*snapshot/i);
assert.doesNotMatch(el('processDetailSignature').textContent,/Example signer/);
""")

    def test_unavailable_details_are_inline_and_can_be_retried(self):
        self.run_js("""
apiImpl=async()=>{throw Error('Access denied')};await ProcessWorkspace.open(1);
assert.match(el('processDetailStatus').textContent,/Access denied/);assert.match(el('processDetailStatus').textContent,/unavailable/i);
apiImpl=async()=>({process:sample(1)});await ProcessWorkspace.open(1);assert.equal(calls.length,2);
assert.equal(el('processDrawer').hidden,false);assert.equal(notifications.length,0);
""")

    def test_missing_or_mismatched_detail_payload_cannot_display_wrong_process(self):
        self.run_js("""
apiImpl=async()=>({process:sample(2)});await ProcessWorkspace.open(1);
assert.match(el('processDetailStatus').textContent,/unavailable/i);assert.doesNotMatch(el('processDrawerTitle').textContent,/App 2/);
apiImpl=async()=>({});await ProcessWorkspace.open(1);assert.match(el('processDetailStatus').textContent,/unavailable/i);
""")

    def test_reused_pid_with_changed_start_time_and_same_path_is_not_displayed_or_cached(self):
        self.run_js("""
snapshot=[sample(1,100,{started_at:'2026-01-01T00:00:00Z'})];ProcessWorkspace.render();
apiImpl=async()=>({process:sample(1,200,{started_at:'2026-01-01T00:01:00Z',friendly_name:'Replacement',
    signature:{status:'Valid',publisher:'Replacement signer'},sha256:'replacement-hash',command_line:'replacement-command'})});
await ProcessWorkspace.open(1);
assert.equal(el('processDrawerTitle').textContent,'App 1');
assert.match(el('processDetailStatus').textContent,/unavailable/i);assert.match(el('processDetailStatus').textContent,/refresh/i);
assert.doesNotMatch(el('processDetail').textContent,/Replacement|replacement-hash|replacement-command/);
for(const key of ['path','hash','command'])assert.equal(doc.querySelector('[data-process-copy="'+key+'"]').disabled,true);
ProcessWorkspace.close();await ProcessWorkspace.open(1);assert.equal(calls.length,2,'A mismatched response must not be cached');
""")

    def test_reused_pid_with_changed_path_is_rejected_even_without_or_with_matching_start_time(self):
        for started_at in (None, "2026-01-01T00:00:00Z"):
            with self.subTest(started_at=started_at):
                self.run_js("const startedAt=" + json.dumps(started_at) + ";" + r"""
snapshot=[sample(1,100,{started_at:startedAt})];ProcessWorkspace.render();
apiImpl=async()=>({process:sample(1,200,{started_at:startedAt,executable_path:'C:\\Other\\app1.exe',
    friendly_name:'Replacement',signature:{status:'Valid',publisher:'Replacement signer'},sha256:'replacement-hash'})});
await ProcessWorkspace.open(1);
assert.equal(el('processDrawerTitle').textContent,'App 1');
assert.match(el('processDetailStatus').textContent,/unavailable/i);assert.match(el('processDetailStatus').textContent,/refresh/i);
assert.doesNotMatch(el('processDetail').textContent,/Replacement|replacement-hash|Other/);
ProcessWorkspace.close();await ProcessWorkspace.open(1);assert.equal(calls.length,2);
""")

    def test_reused_pid_signature_never_enriches_or_sorts_the_original_snapshot_row(self):
        for changed in ("start", "path"):
            with self.subTest(changed=changed):
                self.run_js("const changed=" + json.dumps(changed) + ";" + r"""
snapshot=[sample(1,100,{started_at:'old',signature:{status:'Z snapshot'}}),
    sample(2,100,{signature:{status:'M snapshot'}})];ProcessWorkspace.render();
apiImpl=async()=>({process:sample(1,200,{started_at:changed==='start'?'new':'old',
    executable_path:changed==='path'?'C:\\Other\\app1.exe':snapshot[0].executable_path,
    signature:{status:'A replacement'}})});
await ProcessWorkspace.open(1);
const rowSignature=()=>rows().find(row=>row.dataset.pid==='1').querySelector('[data-process-signature]').textContent;
assert.equal(rowSignature(),'Z snapshot','Opening must not attribute a reused PID signature to the old row');
ProcessWorkspace.render();assert.equal(rowSignature(),'Z snapshot','Rerendering must not use a mismatched cache entry');
sort('signature');assert.deepEqual(pids(),[2,1],'Signature sort must use evidence belonging to each snapshot row');
assert.equal(snapshot[0].signature.status,'Z snapshot');
""")

    def test_matching_instance_details_remain_cached_with_available_identity_fields(self):
        cases = [
            ({"started_at": "same"}, {"started_at": "same"}),
            ({"started_at": "snapshot-only"}, {}),
            ({}, {"started_at": "detail-only"}),
            ({"started_at": "same", "executable_path": ""}, {"started_at": "same"}),
            ({}, {"executable_path": "c:/programs/APP1.EXE", "name": "APP1.EXE"}),
        ]
        for snapshot_fields, detail_fields in cases:
            with self.subTest(snapshot=snapshot_fields, detail=detail_fields):
                self.run_js("const snapshotFields=" + json.dumps(snapshot_fields) +
                            ";const detailFields=" + json.dumps(detail_fields) + ";" + """
snapshot=[sample(1,100,snapshotFields)];ProcessWorkspace.render();
apiImpl=async()=>({process:sample(1,200,{...detailFields,signature:{status:'Valid',publisher:'Legitimate signer'},sha256:'legitimate-hash'})});
await ProcessWorkspace.open(1);assert.match(el('processDetailSignature').textContent,/Legitimate signer|legitimate-hash/);
assert.equal(rows()[0].querySelector('[data-process-signature]').textContent,'Valid');
ProcessWorkspace.close();ProcessWorkspace.render();await ProcessWorkspace.open(1);
assert.equal(calls.length,1,'Compatible partial identity must not disable legitimate cache reuse');
assert.equal(el('processDetailStatus').textContent,'');assert.equal(doc.querySelector('[data-process-copy="hash"]').disabled,false);
""")

    def test_name_only_identity_cannot_authorize_verified_details_or_row_enrichment(self):
        self.run_js("""
snapshot=[sample(1,100,{executable_path:'',started_at:null})];ProcessWorkspace.render();
apiImpl=async()=>({process:sample(1,200,{executable_path:'',started_at:null,
    signature:{status:'Valid',publisher:'Unconfirmed signer'},sha256:'unconfirmed-hash',command_line:'unconfirmed-command'})});
await ProcessWorkspace.open(1);
assert.match(el('processDetailStatus').textContent,/unavailable/i);assert.match(el('processDetailStatus').textContent,/refresh/i);
assert.doesNotMatch(el('processDetail').textContent,/Unconfirmed signer|unconfirmed-hash|unconfirmed-command/);
assert.equal(rows()[0].querySelector('[data-process-signature]').textContent,'Unavailable');
ProcessWorkspace.close();await ProcessWorkspace.open(1);assert.equal(calls.length,2);
""")

    def test_pid_only_identity_cannot_authorize_details(self):
        self.run_js("""
snapshot=[sample(1,100,{name:null,executable_path:null})];ProcessWorkspace.render();
apiImpl=async()=>({process:sample(1,200,{name:null,executable_path:null,
    signature:{status:'Valid',publisher:'Unconfirmed signer'},sha256:'unconfirmed-hash'})});
await ProcessWorkspace.open(1);
assert.match(el('processDetailStatus').textContent,/unavailable/i);assert.match(el('processDetailStatus').textContent,/refresh/i);
assert.doesNotMatch(el('processDetailSignature').textContent,/Unconfirmed signer|unconfirmed-hash/);
ProcessWorkspace.close();await ProcessWorkspace.open(1);assert.equal(calls.length,2);
""")

    def test_protected_missing_path_preserves_unavailable_errors_without_claiming_identity(self):
        for snapshot_path in ("", "C:\\Programs\\app1.exe"):
            with self.subTest(snapshot_path=snapshot_path):
                self.run_js("const snapshotPath=" + json.dumps(snapshot_path) + ";" + """
snapshot=[sample(1,100,{executable_path:snapshotPath})];ProcessWorkspace.render();
apiImpl=async()=>({process:sample(1,null,{executable_path:'',parent_pid:0,command_line:'unconfirmed-command',
    signature:{status:'Unavailable',error:'Protected path inaccessible'},hash_error:'Hash skipped'})});
await ProcessWorkspace.open(1);
assert.match(el('processDetailOverview').textContent,/Parent PID\\s*0/);
assert.match(el('processDetailSignature').textContent,/Protected path inaccessible/);
assert.match(el('processDetailSignature').textContent,/Hash skipped/);
assert.match(el('processDetailStatus').textContent,/unavailable/i);assert.match(el('processDetailStatus').textContent,/refresh/i);
assert.doesNotMatch(el('processDetailTechnical').textContent,/unconfirmed-command/);
assert.equal(doc.querySelector('[data-process-copy="hash"]').disabled,true);
ProcessWorkspace.close();await ProcessWorkspace.open(1);assert.equal(calls.length,2,'Unconfirmed identity must not be cached');
""")

    def test_conflicting_name_rejects_partial_detail_even_when_file_evidence_is_unavailable(self):
        self.run_js("""
snapshot=[sample(1,100,{executable_path:''})];ProcessWorkspace.render();
apiImpl=async()=>({process:sample(1,null,{name:'replacement.exe',friendly_name:'Replacement',executable_path:'',
    signature:{status:'Unavailable',error:'Replacement error'},hash_error:'Replacement hash error'})});
await ProcessWorkspace.open(1);
assert.equal(el('processDrawerTitle').textContent,'App 1');
assert.match(el('processDetailStatus').textContent,/unavailable/i);assert.match(el('processDetailStatus').textContent,/refresh/i);
assert.doesNotMatch(el('processDetail').textContent,/Replacement/);
""")

    def test_detail_without_a_snapshot_instance_is_unavailable_and_not_cached(self):
        self.run_js("""
snapshot=[];ProcessWorkspace.render();await ProcessWorkspace.open(1);
assert.match(el('processDetailStatus').textContent,/unavailable/i);assert.match(el('processDetailStatus').textContent,/refresh/i);
assert.doesNotMatch(el('processDetailSignature').textContent,/Example signer/);
snapshot=[sample(1)];ProcessWorkspace.render();await ProcessWorkspace.open(1);
assert.match(el('processDetailSignature').textContent,/Example signer/);
assert.equal(calls.length,2);
""")

    def test_slow_reused_pid_detail_does_not_poison_rows_or_newer_selection(self):
        self.run_js("""
snapshot=[sample(1,100,{started_at:'old'}),sample(2)];ProcessWorkspace.render();
const old=deferred();apiImpl=url=>url.endsWith('/1')?old.promise:Promise.resolve({process:sample(2,200,{signature:{status:'Valid',publisher:'Current signer'}})});
const opening=ProcessWorkspace.open(1);await ProcessWorkspace.open(2);
old.resolve({process:sample(1,200,{started_at:'new',signature:{status:'Replacement'}})});await opening;
assert.equal(el('processDrawerTitle').textContent,'App 2');assert.match(el('processDetailSignature').textContent,/Current signer/);
ProcessWorkspace.render();assert.equal(rows().find(row=>row.dataset.pid==='1').querySelector('[data-process-signature]').textContent,'Unavailable');
await ProcessWorkspace.open(1);assert.equal(calls.length,3,'An old mismatched response must not populate cache in the background');
""")

    def test_refresh_after_pid_reuse_accepts_and_caches_the_new_snapshot_instance(self):
        self.run_js("""
snapshot=[sample(1,100,{started_at:'old'})];ProcessWorkspace.render();
const replacement=sample(1,200,{started_at:'new',signature:{status:'Valid',publisher:'New instance signer'}});
apiImpl=async()=>({process:replacement});await ProcessWorkspace.open(1);
assert.doesNotMatch(el('processDetailSignature').textContent,/New instance signer/);
snapshot=[{...replacement,signature:undefined}];await ProcessWorkspace.onSnapshot();
assert.match(el('processDetailSignature').textContent,/New instance signer/);
assert.equal(rows()[0].querySelector('[data-process-signature]').textContent,'Valid');
ProcessWorkspace.close();await ProcessWorkspace.open(1);assert.equal(calls.length,2);
""")

    def test_old_reused_pid_response_cannot_replace_refreshed_instance_cache(self):
        self.run_js("""
snapshot=[sample(1,100,{started_at:'old'})];ProcessWorkspace.render();
const old=deferred(),fresh=deferred();apiImpl=()=>calls.length===1?old.promise:fresh.promise;
const opening=ProcessWorkspace.open(1);snapshot=[sample(1,200,{started_at:'new'})];
const refreshing=ProcessWorkspace.onSnapshot();
fresh.resolve({process:sample(1,200,{started_at:'new',signature:{status:'Valid',publisher:'Fresh signer'}})});await refreshing;
old.resolve({process:sample(1,300,{started_at:'other',signature:{status:'Stale',publisher:'Stale signer'}})});await opening;
assert.match(el('processDetailSignature').textContent,/Fresh signer/);assert.doesNotMatch(el('processDetailSignature').textContent,/Stale signer/);
ProcessWorkspace.close();await ProcessWorkspace.open(1);assert.equal(calls.length,2);
assert.equal(rows()[0].querySelector('[data-process-signature]').textContent,'Valid');
""")

    def test_missing_evidence_is_explicit_parent_zero_is_preserved_and_signature_is_not_safety(self):
        self.run_js(r"""
apiImpl=async()=>({process:sample(1,null,{publisher:'',executable_path:'',parent_pid:0,
    signature:{status:'Unavailable',error:'Path inaccessible'},hash_error:'Hash skipped'})});
await ProcessWorkspace.open(1);
assert.match(el('processDetailOverview').textContent,/Parent PID\s*0/);
assert.match(el('processDetailOverview').textContent,/Unavailable/);
el('processTabSignature').click();const text=el('processDetailSignature').textContent;
assert.match(text,/Path inaccessible/);assert.match(text,/Hash skipped/);assert.match(text,/does not prove.*safe/i);
assert.equal(doc.querySelector('[data-process-copy="hash"]').disabled,true);
""")

    def test_signature_metadata_original_filename_and_hash_use_backend_fields(self):
        self.run_js("""
apiImpl=async()=>({process:sample(1,0,{signature:{status:'Valid',publisher:'Signer subject',company_name:'Company',
    original_filename:'ORIGINAL.EXE',file_description:'Description',product_name:'Product',error:null},sha256:'abc'})});
await ProcessWorkspace.open(1);el('processTabSignature').click();
assert.match(el('processDetailSignature').textContent,/Signer subject/);assert.match(el('processDetailSignature').textContent,/abc/);
el('processTabTechnical').click();assert.match(el('processDetailTechnical').textContent,/ORIGINAL.EXE/);
""")

    def test_long_command_is_collapsed_and_copy_uses_full_evidence(self):
        self.run_js("""
await ProcessWorkspace.open(1);el('processTabTechnical').click();
assert.equal(el('processCommandToggle').getAttribute('aria-expanded'),'false');
const full=el('processCommand').textContent;assert.ok(full.length>900);
el('processCommandToggle').click();assert.equal(el('processCommandToggle').getAttribute('aria-expanded'),'true');
doc.querySelector('[data-process-copy="command"]').click();await flush();assert.equal(copied[0],full);
el('processTabSignature').click();doc.querySelector('[data-process-copy="hash"]').click();await flush();
assert.equal(copied[1],'a'.repeat(64));assert.equal(notifications.length,0);
""")

    def test_copy_failure_is_contained_without_leaking_evidence_in_notification(self):
        self.run_js("""
bridge.copyText=async()=>{throw Error('SECRET path')};ProcessWorkspace.init(bridge);await ProcessWorkspace.open(1);
el('processTabTechnical').click();doc.querySelector('[data-process-copy="path"]').click();await flush();
assert.match(el('processDetailStatus').textContent,/copy|clipboard/i);
assert.ok(notifications.every(args=>!JSON.stringify(args).includes('SECRET')));
""")

    def test_escape_closes_and_restores_opener_without_changing_list_scroll(self):
        self.run_js("""
const opener=rows()[2].querySelector('button');opener.focus();el('processTableScroll').scrollTop=170;
await ProcessWorkspace.open(opener.dataset.pid,opener);const key=f.key(el('processDrawerClose'),'Escape');
assert.equal(key.defaultPrevented,true);assert.equal(el('processDrawer').hidden,true);
assert.equal(doc.activeElement,opener);assert.equal(el('processTableScroll').scrollTop,170);
assert.equal(el('fixtureOpener').inert,false);
""")

    def test_focus_restores_to_replacement_row_after_refresh_or_filter_fallback(self):
        self.run_js("""
const opener=rows()[0].querySelector('button');opener.focus();await ProcessWorkspace.open(opener.dataset.pid,opener);
ProcessWorkspace.render();ProcessWorkspace.close();assert.ok(el('processRows').contains(doc.activeElement));
await ProcessWorkspace.open(1);el('processFilter').value='not-found';ProcessWorkspace.render();ProcessWorkspace.close();
assert.equal(doc.activeElement,el('processFilter'));
""")

    def test_programmatic_open_without_opener_restores_to_selected_details_action(self):
        self.run_js("""
doc.activeElement=doc.body;await ProcessWorkspace.open(1);ProcessWorkspace.close();
assert.equal(doc.activeElement.dataset.pid,'1');assert.equal(doc.activeElement.tagName,'BUTTON');
""")

    def test_close_preserves_preexisting_inert_and_scroll_lock_state(self):
        self.run_js("""
el('fixtureOpener').inert=true;doc.body.style.overflow='clip';await ProcessWorkspace.open(1);ProcessWorkspace.close();
assert.equal(el('fixtureOpener').inert,true);assert.equal(doc.body.style.overflow,'clip');
ProcessWorkspace.close();assert.equal(doc.body.style.overflow,'clip');
""")

    def test_selection_and_drawer_survive_filter_changes_without_refetching(self):
        self.run_js("""
const opener=rows().find(row=>row.dataset.pid==='1').querySelector('button');await ProcessWorkspace.open(1,opener);
el('processFilter').value='app61.exe';ProcessWorkspace.render();assert.deepEqual(pids(),[61]);
assert.equal(el('processDrawer').hidden,false);assert.match(el('processDrawerTitle').textContent,/App 1/);assert.equal(calls.length,1);
ProcessWorkspace.close();assert.equal(doc.activeElement,el('processFilter'));
""")

    def test_tab_trap_wraps_both_directions_and_outside_focus_is_contained(self):
        self.run_js("""
await ProcessWorkspace.open(1);const drawer=el('processDrawer');
const visible = e => {for(let n=e;n&&n!==drawer;n=n.parentElement)if(n.hidden)return false;return !e.disabled&&e.tabIndex>=0};
const controls=drawer.querySelectorAll('button, [href], input, select, textarea, [tabindex]').filter(visible);
controls.at(-1).focus();assert.equal(f.key(controls.at(-1),'Tab').defaultPrevented,true);assert.equal(doc.activeElement,controls[0]);
assert.equal(f.key(controls[0],'Tab',{shiftKey:true}).defaultPrevented,true);assert.equal(doc.activeElement,controls.at(-1));
el('fixtureOpener').focus();assert.ok(drawer.contains(doc.activeElement));assert.equal(el('fixtureOpener').inert,true);
""")

    def test_tab_arrow_home_end_keys_manage_roving_focus_and_panels(self):
        self.run_js("""
await ProcessWorkspace.open(1);el('processTabOverview').focus();f.key(el('processTabOverview'),'ArrowRight');
assert.equal(doc.activeElement,el('processTabSignature'));assert.equal(el('processDetailSignature').hidden,false);
assert.equal(el('processDetailOverview').hidden,true);assert.equal(el('processTabOverview').tabIndex,-1);
f.key(el('processTabSignature'),'End');assert.equal(doc.activeElement,el('processTabTechnical'));
f.key(el('processTabTechnical'),'Home');assert.equal(doc.activeElement,el('processTabOverview'));
""")

    def test_loading_error_empty_and_partial_data_do_not_claim_clean_results(self):
        self.run_js("""
ProcessWorkspace.setLoading(true);assert.equal(el('processTableScroll').getAttribute('aria-busy'),'true');assert.equal(rows().length,25);
ProcessWorkspace.setError(Error('Snapshot denied'));assert.match(el('processStatus').textContent,/Snapshot denied/);
assert.equal(rows().length,25);snapshot=[];ProcessWorkspace.render();assert.match(el('processRows').textContent,/Snapshot denied/);
ProcessWorkspace.setError(null);ProcessWorkspace.setLoading(false);assert.match(el('processRows').textContent,/refresh|snapshot/i);
snapshot=[sample(1,null,{executable_path:''})];ProcessWorkspace.render();assert.match(el('processStatus').textContent,/unavailable|partial/i);
""")

    def test_table_and_drawer_escape_untrusted_process_evidence(self):
        self.run_js("""
const hostile='<img src=x onerror=alert(1)>';snapshot=[sample(1,1,{friendly_name:hostile,publisher:hostile})];ProcessWorkspace.render();
assert.equal(el('processRows').querySelector('img'),null);assert.match(el('processRows').textContent,/<img/);
apiImpl=async()=>({process:sample(1,1,{command_line:hostile,signature:{status:hostile,error:hostile}})});
await ProcessWorkspace.open(1);assert.equal(el('processDetail').querySelector('img'),null);
el('processTabTechnical').click();assert.equal(el('processCommand').textContent,hostile);
""")

    def test_init_is_idempotent_and_legacy_events_remain_parent_owned(self):
        self.run_js("""
ProcessWorkspace.init(bridge);ProcessWorkspace.render();el('processNext').click();assert.equal(rows().length,25);
assert.match(el('processPageInfo').textContent,/26/);
for(const id of ['processFilter','processPublisherFilter','processGroupBy','processReviewFilter','needsReviewOnly',
    'processRows','refreshProcesses','downloadProcessReport','downloadVerificationReport'])
    assert.equal(Object.values(el(id).listeners).flat().length,0,id+' remains owned by core');
""")


if __name__ == "__main__":
    unittest.main()
