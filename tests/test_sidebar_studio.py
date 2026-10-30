"""Offline presentation contracts and actual controller behavior (not visual QA)."""

from html.parser import HTMLParser
import json
from pathlib import Path
import re
import subprocess
import unittest

from test_installer_review import dashboard


ROOT = Path(dashboard.__file__).resolve().parent


class Elements(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.ids = {}
        self.duplicates = []
        self.tags = []
        self.feed(source)

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        self.tags.append((tag, attrs))
        if "id" in attrs:
            if attrs["id"] in self.ids:
                self.duplicates.append(attrs["id"])
            self.ids[attrs["id"]] = (tag, attrs)


class StudioMarkupTests(unittest.TestCase):
    def setUp(self):
        self.html = dashboard.build_dashboard_html()
        self.dom = Elements(self.html)

    def test_shell_has_semantic_sidebar_skip_link_and_all_existing_screens(self):
        self.assertIn("sidebar", self.dom.ids)
        self.assertEqual(self.dom.ids["sidebar"][0], "aside")
        self.assertIn('href="#workspace"', self.html)
        for view in ("overview", "scan", "results", "processes", "installer", "security", "history", "manual", "about"):
            self.assertIn("tab-" + view, self.dom.ids)
            self.assertIn('data-tab="' + view + '"', self.html)
        self.assertFalse(self.dom.duplicates, self.dom.duplicates)

    def test_scan_advanced_disclosure_does_not_hide_acknowledgement(self):
        self.assertIn("advancedScanSettings", self.dom.ids)
        self.assertEqual(self.dom.ids["advancedScanSettings"][0], "details")
        self.assertNotIn("checked", self.dom.ids["includeReparse"][1])
        self.assertNotIn("checked", self.dom.ids["ackSafety"][1])
        self.assertIn('aria-describedby="scanSafetyNotice"', self.html)

    def test_result_views_and_bounded_pagination_controls_exist(self):
        for view in ("folders", "files", "types", "tree", "health"):
            self.assertIn('data-result-view="' + view + '"', self.html)
            self.assertIn("result-" + view, self.dom.ids)
        for kind in ("folders", "files", "types", "skipped"):
            for suffix in ("PageSize", "Previous", "Next", "PageInfo"):
                self.assertIn(kind + suffix, self.dom.ids)

    def test_local_assets_are_embedded_without_network_dependencies(self):
        self.assertIn("const Studio =", self.html)
        self.assertIn("--sidebar-width: 240px", self.html)
        for tag, attrs in self.dom.tags:
            if tag == "script":
                self.assertNotIn("src", attrs)
            if tag in ("link", "img", "iframe"):
                self.assertFalse(attrs.get("src", attrs.get("href", "")).startswith(("http:", "https:", "//")))

    def test_css_has_requested_palette_focus_reduced_motion_and_drawer(self):
        for token in ("#172B46", "#2563EB", "#16A085", "#F4F7FB", "64px", ":focus-visible", "prefers-reduced-motion", "max-width: 900px", "max-width: 600px"):
            self.assertIn(token, self.html)

    def test_all_embedded_javascript_is_valid(self):
        self.assertIn("const Studio =", self.html)
        scripts = self.html.split("<script>")[1:]
        for script in scripts:
            result = subprocess.run(["node", "--check"], input=script.split("</script>", 1)[0],
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_local_only_indicator_is_not_hidden_in_mobile_layout(self):
        css = (ROOT / 'ui' / 'sidebar_studio.css').read_text(encoding='utf-8')
        self.assertNotIn('.topbar .local-indicator { display: none; }', css)

    def test_toast_positioning_is_scoped_to_dynamic_alert_not_legacy_panels(self):
        css = (ROOT / 'ui' / 'sidebar_studio.css').read_text(encoding='utf-8')
        fixed = [selector.strip() for selector, body in re.findall(r'([^{}]+)\{([^{}]*)\}', css)
                 if 'position: fixed' in body and 'action-alert' in selector]
        self.assertFalse(fixed, fixed)
        self.assertRegex(css, r'#actionAlert\s*\{[^}]*position:\s*fixed')

    def test_mobile_width_overrides_collapsed_preference_and_short_sidebar_scrolls(self):
        css = (ROOT / 'ui' / 'sidebar_studio.css').read_text(encoding='utf-8')
        mobile = css.split('@media (max-width: 900px)', 1)[1]
        self.assertRegex(mobile, r'body,\s*body\.sidebar-collapsed\s*\{[^}]*--sidebar-width:\s*240px')
        self.assertRegex(css, r'\.sidebar\s*\{[^}]*overflow-y:\s*auto')

    def test_legacy_outer_layouts_use_container_safe_metric_tracks(self):
        css = (ROOT / 'ui' / 'sidebar_studio.css').read_text(encoding='utf-8')
        self.assertRegex(css, r'#tab-security \.grid[^}]*repeat\(auto-fit,\s*minmax\(110px,\s*1fr\)\)')
        self.assertIn('#tab-security .security-layout > div', css)


class StudioControllerTests(unittest.TestCase):
    def run_js(self, assertions):
        path = ROOT / "ui" / "sidebar_studio.js"
        self.assertTrue(path.is_file(), "Sidebar Studio controller has not been implemented")
        code = "const assert = require('node:assert/strict');\nconst Studio = require(" + json.dumps(str(path)) + ");\n" + assertions
        result = subprocess.run(["node", "-"], input=code, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def run_dom(self, assertions, narrow=False, preferences=None):
        parsed = Elements(dashboard.build_dashboard_html())
        metadata = parsed.ids
        for index, (tag, attrs) in enumerate(parsed.tags):
            if 'data-tab' in attrs and 'id' not in attrs:
                metadata['fixture_nav_' + str(index)] = (tag, attrs)
        setup = "const {createFixture}=require(" + json.dumps(str(ROOT / "tests" / "studio_dom_fixture.js")) + ");\n"
        setup += "const f=createFixture(" + json.dumps(metadata) + "," + json.dumps(narrow) + "," + json.dumps(preferences) + ");\n"
        setup += "global.directoryFromPath=path=>String(path).slice(0,String(path).lastIndexOf('/'));\n"
        setup += "global.showTab=name=>Studio.navigate(name,true);global.openHistory=()=>{};Studio.init(f.doc,f.win);\n"
        self.run_js(setup + assertions)

    def core_functions(self, *names):
        script = dashboard.build_dashboard_html().split('<script>', 1)[1].split('</script>', 1)[0]
        functions = []
        for name in names:
            match = re.search(r'^(?:async )?function ' + re.escape(name) + r'\([^)]*\) \{.*?^\}', script, re.M | re.S)
            self.assertIsNotNone(match, name)
            functions.append(match.group())
        return '\n'.join(functions)

    def test_preferences_reject_unknown_views_and_do_not_restore_reparse_or_secrets(self):
        self.run_js("""
const p = Studio.validatePreferences({view:'https://bad.invalid', resultView:'unknown', collapsed:'false',
    includeReparse:true, root:'PRIVATE', csrf_token:'SECRET', acknowledgeSafety:true});
assert.deepEqual(p, {view:'overview',resultView:'folders',collapsed:false});
assert.deepEqual(Studio.validatePreferences({view:'history',resultView:'tree',collapsed:true}),
    {view:'history',resultView:'tree',collapsed:true});
""")

    def test_storage_unavailable_or_corrupt_does_not_break_startup(self):
        self.run_js("""
assert.equal(Studio.readPreferences({getItem(){throw Error('denied')}}).view,'overview');
assert.equal(Studio.readPreferences({getItem(){return '{'}}).view,'overview');
assert.equal(Studio.readPreferences({getItem(){return 'null'}}).view,'overview');
assert.doesNotThrow(()=>Studio.savePreferences({setItem(){throw Error('denied')}},{view:'scan'}));
""")

    def test_preferences_save_only_validated_non_private_fields(self):
        self.run_js("""
let saved;
Studio.savePreferences({setItem(key,value){saved=JSON.parse(value)}},{view:'results',resultView:'files',collapsed:true,root:'PRIVATE'});
assert.deepEqual(saved,{view:'results',resultView:'files',collapsed:true});
""")

    def test_pagination_filters_before_slicing_and_clamps_pages(self):
        self.run_js("""
const rows=Array.from({length:230},(_,i)=>({path:'Folder '+i,bytes:i}));
const page=Studio.pageRows(rows,{page:999,pageSize:25,query:'Folder 2'});
assert.equal(page.total,41);assert.equal(page.page,2);assert.equal(page.rows.length,16);
assert(page.rows.every(r=>r.path.includes('Folder 2')));
""")

    def test_page_sizes_allow_only_25_50_or_100(self):
        self.run_js("""
const rows=Array.from({length:500},(_,i)=>({bytes:i}));
for(const pageSize of [25,50,100])assert.equal(Studio.pageRows(rows,{pageSize}).rows.length,pageSize);
for(const pageSize of [-1,0,1000,'50',null])assert.equal(Studio.pageRows(rows,{pageSize}).rows.length,25);
""")

    def test_size_sort_uses_bytes_not_display_text(self):
        self.run_js("""
const rows=[{path:'A',bytes:9,size:'9 GB'},{path:'B',bytes:1024,size:'1 KB'},{path:'C',size:'Unavailable'}];
assert.deepEqual(Studio.pageRows(rows,{sort:'bytes-desc'}).rows.map(r=>r.path),['B','A','C']);
assert.deepEqual(Studio.pageRows(rows,{sort:'bytes-asc'}).rows.map(r=>r.path),['A','B','C']);
""")

    def test_empty_malformed_rows_and_no_matches_have_stable_page_state(self):
        self.run_js("""
for(const rows of [null,[],[null,1,'bad']]){
 const p=Studio.pageRows(rows,{query:'nothing',page:9});
 assert.equal(p.total,0);assert.equal(p.page,1);assert.equal(p.pages,1);assert.deepEqual(p.rows,[]);
}
""")

    def test_search_handles_case_and_metadata_without_mutating_rows(self):
        self.run_js("""
const rows=[{path:'Z:/Fixture/Alpha',bytes:10},{extension:'.TXT',bytes:3,count:7}];
const before=JSON.stringify(rows);
assert.equal(Studio.pageRows(rows,{query:'alpha'}).total,1);
assert.equal(Studio.pageRows(rows,{query:'.txt'}).total,1);
assert.equal(JSON.stringify(rows),before);
""")

    def test_overview_empty_state_does_not_invent_disk_capacity(self):
        self.run_js("""
const model=Studio.overviewModel(null,[]);
assert.equal(model.hasRecord,false);assert.equal(model.size,'Not recorded');assert.deepEqual(model.folders,[]);
assert(!('capacity' in model));assert(!('freeSpace' in model));
""")

    def test_overview_uses_recorded_totals_and_limits_lists_to_five(self):
        self.run_js("""
const folders=Array.from({length:20},(_,i)=>({path:'Fixture '+i,bytes:i}));
const model=Studio.overviewModel({status:'completed',result:{summary:{total_size:'7 GB',files_scanned:12,folders_scanned:3,skipped_count:2},top_folders:folders}},folders);
assert.equal(model.size,'7 GB');assert.equal(model.files,12);assert.equal(model.skipped,2);
assert.equal(model.folders.length,5);assert.equal(model.recent.length,5);
assert.equal(model.folders[0].bytes,19);
""")

    def test_cancelled_and_failed_records_cannot_claim_clean_coverage(self):
        self.run_js("""
for(const status of ['cancelled','error','failed']){
 const h=Studio.healthModel({status,result:{scan_health:{level:'success',title:'Clean'},summary:{skipped_count:0}}});
 assert.equal(h.level,'warning');assert(h.title.toLowerCase().includes('partial'));
}
assert.equal(Studio.healthModel({status:'completed',result:{}}).level,'info');
""")

    def test_notifications_retain_critical_details_after_routine_success(self):
        self.run_js("""
let list=[];
list=Studio.addNotification(list,{type:'error',title:'Fixture failure',details:['Permission denied']});
list=Studio.addNotification(list,{type:'success',title:'Copied',message:'Done'});
assert.equal(list.length,2);assert.equal(list[0].type,'success');
assert.equal(list[1].details[0],'Permission denied');
for(let i=0;i<100;i++)list=Studio.addNotification(list,{type:'info',title:'Routine '+i});
assert(list.some(n=>n.type==='error'));assert(list.length<=50);
""")

    def test_duplicate_notifications_do_not_grow_on_polling(self):
        self.run_js("""
let list=[];for(let i=0;i<20;i++)list=Studio.addNotification(list,{type:'error',title:'Same',message:'Offline'});
assert.equal(list.length,1);
""")

    def test_completed_scan_notice_retains_incomplete_or_unknown_coverage(self):
        self.run_js("""
for(const result of [{summary:{skipped_count:3},scan_health:{level:'warning'}},{summary:{skipped_count:0}}])
 assert.equal(Studio.completionNotice({status:'completed',result}).type,'warning');
assert.equal(Studio.completionNotice({status:'completed',result:{summary:{skipped_count:0},scan_health:{level:'success'}}}).type,'success');
assert.equal(Studio.completionNotice({status:'cancelled'}).type,'warning');
assert.equal(Studio.completionNotice({status:'failed'}).type,'error');
""")

    def test_tree_identity_includes_record_and_html_but_not_view_or_filters(self):
        self.run_js("""
const a={scan_id:'fixtureA',result:{tree_html:'<div>A</div>'}};
assert.equal(Studio.treeIdentity(a),Studio.treeIdentity({...a,other:'ignored'}));
assert.notEqual(Studio.treeIdentity(a),Studio.treeIdentity({...a,scan_id:'fixtureB'}));
assert.notEqual(Studio.treeIdentity(a),Studio.treeIdentity({...a,result:{tree_html:'<div>B</div>'}}));
""")

    def test_navigation_keeps_one_page_active_and_restores_valid_preferences(self):
        self.run_dom("""
for(const view of ['overview','scan','results','processes','installer','security','history','manual','about']){
 assert.equal(Studio.navigate(view,true),view);
 assert.equal(f.doc.querySelectorAll('.tab-panel').filter(n=>!n.classList.contains('hidden')).length,1);
 assert(!f.element('tab-'+view).classList.contains('hidden'));
 assert.equal(f.doc.querySelectorAll('.tab').filter(n=>n.getAttribute('aria-current')==='page').length,1);
 assert.equal(f.preferences().view,view);assert.equal(f.doc.activeElement.id,'pageTitle');
}
assert.equal(Studio.navigate('unknown'),'overview');
""", preferences={"view": "history", "resultView": "files", "collapsed": False})

    def test_sidebar_collapse_expand_updates_accessible_state_and_storage(self):
        self.run_dom("""
f.element('collapseSidebar').dispatch('click');
assert(f.doc.body.classList.contains('sidebar-collapsed'));
assert.equal(f.element('collapseSidebar').getAttribute('aria-expanded'),'false');
assert.equal(f.element('collapseSidebar').getAttribute('aria-label'),'Expand sidebar');
assert.equal(f.preferences().collapsed,true);
f.element('collapseSidebar').dispatch('click');
assert(!f.doc.body.classList.contains('sidebar-collapsed'));
assert.equal(f.element('collapseSidebar').getAttribute('aria-expanded'),'true');
""")

    def test_mobile_drawer_sets_inert_and_escape_restores_opener_focus(self):
        self.run_dom("""
assert.equal(f.element('sidebar').inert,true);
f.element('openSidebar').dispatch('click');
assert.equal(f.element('openSidebar').getAttribute('aria-expanded'),'true');
assert.equal(f.element('sidebar').getAttribute('aria-modal'),'true');
assert.equal(f.element('appContent').inert,true);assert.equal(f.doc.activeElement.id,'closeSidebar');
f.doc.dispatch('keydown',{key:'Escape',preventDefault(){}});
assert.equal(f.element('appContent').inert,false);assert.equal(f.element('sidebar').inert,true);
assert.equal(f.doc.activeElement.id,'openSidebar');
""", narrow=True)

    def test_mobile_drawer_traps_tab_and_releases_on_desktop_resize(self):
        self.run_dom("""
Studio.setDrawer(true);
const buttons=f.element('sidebar').querySelectorAll('button:not([disabled]),a[href]').filter(n=>n.offsetParent!==null);
buttons.at(-1).focus();let prevented=false;
f.doc.dispatch('keydown',{key:'Tab',shiftKey:false,preventDefault(){prevented=true;}});
assert(prevented);assert.equal(f.doc.activeElement,buttons[0]);
f.media.change(false);
assert.equal(f.element('appContent').inert,false);assert.equal(f.element('sidebar').inert,false);
assert(!f.doc.body.classList.contains('sidebar-open'));
""", narrow=True)

    def test_result_subview_keyboard_navigation_sets_selection_and_focus(self):
        self.run_dom("""
const event=f.element('result-tab-folders').dispatch('keydown',{key:'ArrowRight'});
assert(event.prevented);assert.equal(f.element('result-tab-files').getAttribute('aria-selected'),'true');
assert.equal(f.element('result-tab-files').tabIndex,0);assert.equal(f.doc.activeElement.id,'result-tab-files');
assert(f.element('result-folders').classList.contains('hidden'));
f.element('result-tab-files').dispatch('keydown',{key:'End'});
assert.equal(f.doc.activeElement.id,'result-tab-health');
f.element('result-tab-health').dispatch('keydown',{key:'Home'});
assert.equal(f.doc.activeElement.id,'result-tab-folders');
""")

    def test_bound_table_controls_filter_sort_paginate_without_rendering_all_rows(self):
        self.run_dom("""
const record={scan_id:'fixture',status:'completed',result:{summary:{},top_folders:Array.from({length:230},(_,i)=>({path:'Folder '+i,bytes:i,size:i+' B'}))}};
Studio.renderRecord(record);
assert.equal((f.element('topFolders').innerHTML.match(/<tr>/g)||[]).length,25);
assert(f.element('topFolders').innerHTML.includes('Folder 229'));
f.element('foldersNext').dispatch('click');assert(f.element('foldersPageInfo').textContent.includes('Page 2/10'));
f.element('folderFilter').value='Folder 2';f.element('folderFilter').dispatch('input');
assert(f.element('foldersPageInfo').textContent.includes('of 41'));assert(f.element('foldersPageInfo').textContent.includes('Page 1/2'));
f.element('foldersPageSize').value='100';f.element('foldersPageSize').dispatch('change');
assert.equal((f.element('topFolders').innerHTML.match(/<tr>/g)||[]).length,41);
f.element('foldersSort').value='bytes-asc';f.element('foldersSort').dispatch('change');
assert(f.element('topFolders').innerHTML.indexOf('Folder 2<')<f.element('topFolders').innerHTML.indexOf('Folder 20<'));
""")

    def test_paths_and_notifications_escape_untrusted_markup(self):
        self.run_dom("""
Studio.renderRecord({scan_id:'fixture',status:'completed',root:'<script>bad</script>',result:{summary:{},top_folders:[{path:'<img onerror=bad>',size:'1 B',bytes:1}]}});
assert(!f.element('topFolders').innerHTML.includes('<img'));
assert(f.element('topFolders').innerHTML.includes('&lt;img'));
Studio.notify('error','<script>bad</script>','<img onerror=bad>',['<iframe>']);
assert(!f.element('actionAlert').innerHTML.includes('<script>'));
assert(!f.element('notificationList').innerHTML.includes('<iframe>'));
""")

    def test_critical_notification_stays_visible_and_routine_success_is_retained(self):
        self.run_dom("""
Studio.notify('warning','Incomplete coverage','Fixture permission gap',['Details']);
Studio.notify('success','Directory copied','Done');
assert(f.element('actionAlert').innerHTML.includes('Incomplete coverage'));
assert(!f.element('actionAlert').innerHTML.includes('Directory copied'));
assert(f.element('notificationList').innerHTML.includes('Directory copied'));
assert.equal(f.timers.size,0);
f.element('notificationToggle').dispatch('click');assert(!f.element('notificationPanel').classList.contains('hidden'));
assert.equal(f.doc.activeElement.id,'closeNotifications');
f.doc.dispatch('keydown',{key:'Escape'});assert(f.element('notificationPanel').classList.contains('hidden'));
""")

    def test_identical_poll_notifications_do_not_replace_detail_nodes(self):
        self.run_dom("""
Studio.notify('error','Status failed','Offline',['Fixture details']);
const toast=f.element('actionAlert'), list=f.element('notificationList');
const toastWrites=toast.htmlWrites, listWrites=list.htmlWrites;
for(let i=0;i<20;i++)Studio.notify('error','Status failed','Offline',['Fixture details']);
assert.equal(toast.htmlWrites,toastWrites);assert.equal(list.htmlWrites,listWrites);
""")

    def test_new_messages_preserve_existing_notification_entries_and_focused_toast(self):
        self.run_dom("""
Studio.notify('warning','First warning','Incomplete',['Details']);
const list=f.element('notificationList'), entry=list.childNodes[0];assert(entry);
const toast=f.element('actionAlert'), focused=f.node('summary','','Details');toast.appendChild(focused);focused.focus();
const writes=toast.htmlWrites;
Studio.notify('error','Second warning','Another failure',['More details']);
assert(list.childNodes.includes(entry));assert.equal(toast.htmlWrites,writes);assert.equal(f.doc.activeElement,focused);
assert(list.innerHTML.includes('Second warning'));
""")

    def test_tree_reuses_dom_across_render_navigation_and_filter_interactions(self):
        self.run_dom("""
f.doc.templateChildren=[f.tree()];
const record={scan_id:'fixture',status:'completed',result:{summary:{},tree_html:'FIXTURE_TREE'}};
Studio.renderRecord(record);Studio.selectResultView('tree');
const container=f.element('treeView'), node=container.querySelectorAll('details.tree-node')[0];
node.open=false;container.dispatch('toggle',{target:node});container.scrollTop=87;
Studio.navigate('scan');Studio.navigate('results');Studio.renderRecord(record);
assert.equal(container.replacements,1);assert.equal(container.querySelectorAll('details.tree-node')[0],node);
assert.equal(node.open,false);assert.equal(container.scrollTop,87);
""")

    def test_tree_choices_are_scoped_per_record_and_restored_when_returning(self):
        self.run_dom("""
f.doc.templateChildren=[f.tree()];
const a={scan_id:'fixtureA',result:{summary:{},tree_html:'A'}};
const b={scan_id:'fixtureB',result:{summary:{},tree_html:'B'}};
Studio.renderRecord(a);Studio.selectResultView('tree');
let node=f.element('treeView').querySelectorAll('details.tree-node')[0];node.open=false;f.element('treeView').dispatch('toggle',{target:node});
Studio.renderRecord(b);assert.equal(f.element('treeView').querySelectorAll('details.tree-node')[0].open,true);
Studio.renderRecord(a);assert.equal(f.element('treeView').querySelectorAll('details.tree-node')[0].open,false);
""")

    def test_tree_template_copies_only_allowlisted_elements_and_attributes(self):
        self.run_dom("""
const node=f.tree();node.setAttribute('onclick','bad');node.appendChild(f.node('script','','bad'));
node.appendChild(f.node('img','',''));f.doc.templateChildren=[node];
Studio.renderRecord({scan_id:'fixture',result:{summary:{},tree_html:'UNTRUSTED_FIXTURE'}});Studio.selectResultView('tree');
const clean=f.element('treeView').querySelectorAll('details.tree-node')[0];
assert(!clean.hasAttribute('onclick'));assert(!clean.textContent.includes('bad'));
assert(!clean.childNodes.some(n=>n.tagName==='IMG'||n.tagName==='SCRIPT'));
""")

    def test_render_error_clears_previous_metrics_and_rows(self):
        self.run_dom("""
Studio.renderRecord({scan_id:'fixture',result:{summary:{total_size:'PRIVATE_OLD_SIZE'},top_folders:[{path:'OLD_PATH',bytes:1,size:'1 B'}]}});
Studio.recordError({},Error('Malformed fixture'));
assert(!f.element('overviewMetrics').innerHTML.includes('PRIVATE_OLD_SIZE'));
assert(!f.element('topFolders').innerHTML.includes('OLD_PATH'));
assert(f.element('scanHealth').textContent.includes('unavailable'));
assert(f.element('overviewResults').disabled);
""")

    def test_render_error_clears_stale_skipped_counts_and_truncation_state(self):
        self.run_dom("""
Studio.renderRecord({scan_id:'fixture',result:{summary:{skipped_count:987},skipped_truncated:true}});
Studio.recordError({},Error('Malformed fixture'));
assert(!f.element('skippedSummary').textContent.includes('987'));
assert(f.element('skippedTruncation').classList.contains('hidden'));
""")

    def test_scan_action_uses_existing_endpoint_with_actual_boolean_flags(self):
        code = self.core_functions('startScan', 'setExitState', 'updateSecurityCheckStartState', 'showActionAlert')
        self.run_dom("""
global.$=id=>f.element(id);global.window=f.win;
global.state={scanActive:false,securityCheckActive:false,isShuttingDown:false};
const calls=[];global.api=async(path,options)=>{calls.push({path,payload:JSON.parse(options.body)});return {};};
""" + code + """
(async()=>{
 f.element('rootPath').value='Z:/Fixture';f.element('ackSafety').checked=true;
 f.element('includeReparse').checked=false;await startScan();
 assert.equal(calls[0].path,'/api/scans');assert.equal(calls[0].payload.includeReparse,false);
 assert.equal(calls[0].payload.acknowledgeSafety,true);
 f.element('includeReparse').checked=true;await startScan();assert.equal(calls[1].payload.includeReparse,true);
 assert.equal(f.element('operationStatus').textContent,'Scan running');
})().catch(error=>{console.error(error);process.exitCode=1;});
""")

    def test_completed_poll_keeps_selected_history_record_and_tree_dom(self):
        code = self.core_functions('pollStatus', 'setExitState', 'updateSecurityCheckStartState', 'showActionAlert')
        self.run_dom("""
global.$=id=>f.element(id);global.window=f.win;global.esc=Studio.pathHtml;
global.setTimeout=f.win.setTimeout;
const history={scan_id:'selected-history',status:'completed',result:{summary:{},tree_html:'SELECTED'}};
f.doc.templateChildren=[f.tree()];Studio.renderRecord(history);Studio.selectResultView('tree');
const original=f.element('treeView').querySelectorAll('details.tree-node')[0];
global.state={currentRecord:history,scanActive:false,securityCheckActive:false,isShuttingDown:false};
let renders=0;global.renderResult=()=>renders++;global.refreshHistory=async()=>{};
global.api=async()=>({scan_id:'latest-other-scan',status:'completed',active:false,result:{summary:{files_scanned:1,skipped_count:0}}});
""" + code + """
(async()=>{
 await pollStatus();await pollStatus();
 assert.equal(renders,0);assert.equal(state.currentRecord,history);
 assert.equal(f.element('treeView').querySelectorAll('details.tree-node')[0],original);
 assert.equal(f.element('treeView').replacements,1);
 assert(f.element('actionAlert').classList.contains('warning'));
 assert(f.element('notificationToggle').getAttribute('aria-label').includes('1 warnings'));
})().catch(error=>{console.error(error);process.exitCode=1;});
""")


if __name__ == "__main__":
    unittest.main()
