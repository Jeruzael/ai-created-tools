"""Static assembly contracts. These do not verify browser layout or focus."""

from collections import Counter
from html.parser import HTMLParser
import re
import subprocess
import unittest

from test_installer_review import dashboard


class Markup(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.ids=Counter()
        self.scripts=[]
        self.script=None
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attributes=dict(attrs)
        if attributes.get('id'):
            self.ids[attributes['id']]+=1
        if tag=='script':
            self.script=[]

    def handle_data(self, text):
        if self.script is not None:
            self.script.append(text)

    def handle_endtag(self, tag):
        if tag=='script' and self.script is not None:
            self.scripts.append(''.join(self.script))
            self.script=None


class WorkspaceAssemblyTests(unittest.TestCase):
    def test_assembled_dashboard_has_unique_ids_and_all_bound_controls(self):
        markup=Markup(dashboard.build_dashboard_html())
        self.assertEqual({key:count for key,count in markup.ids.items() if count>1},{})
        self.assertEqual(len(markup.scripts),1)
        bound=set(re.findall(r"\$\('([^']+)'\)\.addEventListener\(",markup.scripts[0]))
        self.assertGreater(len(bound),40)
        self.assertEqual(bound-set(markup.ids),set())

    def test_all_workspace_and_report_entry_points_remain_assembled(self):
        markup=Markup(dashboard.build_dashboard_html())
        for name in ['overview','scan','results','processes','installer','security','history','manual','about']:
            self.assertEqual(markup.ids['tab-'+name],1,name)
        for name in ['run','findings','coverage','baselines','allowlist','timeline','reports']:
            self.assertEqual(markup.ids['security-view-'+name],1,name)
        for name in ['downloadProcessReport','downloadVerificationReport','downloadSecurityFullReport',
                     'downloadSecurityFindingsReport','downloadSecurityVerificationReport','downloadSecurityJsonReport',
                     'exportInstallerCandidates','exportInstallerBackupManifest','processVerificationHelp','verification-panel']:
            self.assertEqual(markup.ids[name],1,name)

    def run_process_report(self, assertions):
        script=dashboard.build_dashboard_html().split('<script>',1)[1].split('</script>',1)[0]
        functions=[]
        for name in ['asArray','formatBytes','publisherForProcess','publisherLabel','isUncategorizedProcess',
                     'reviewReasonsForProcess','needsReview','memoryGroupLabel','processMatchesQuery',
                     'getVisibleProcesses','groupProcesses','verificationGuideReportHtml',
                     'buildProcessReportHtml','buildVerificationReportHtml']:
            match=re.search(r'^(?:async )?function '+re.escape(name)+r'\([^)]*\) \{.*?^\}',script,re.M|re.S)
            self.assertIsNotNone(match,name)
            functions.append(match.group())
        setup="""
const assert=require('node:assert/strict');
const esc=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const fields={processFilter:{value:''},processPublisherFilter:{value:''},processGroupBy:{value:'none'},processReviewFilter:{value:''},needsReviewOnly:{checked:false}};
const $=id=>fields[id];
const state={processes:Array.from({length:501},(_,i)=>({pid:i+1,name:'Fixture'+i+'.exe',friendly_name:'Fixture '+i,publisher:'Fixture publisher',memory_bytes:i+1,executable_path:'Z:/Fixture/App'+i+'.exe',review_reasons:['Fixture review'],needs_review:true}))};
"""
        result=subprocess.run(['node','-'],input=setup+'\n'.join(functions)+'\n'+assertions,text=True,capture_output=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_default_grouped_report_labels_actual_grouping_and_exports_all_matching_rows(self):
        self.run_process_report("""
const html=buildProcessReportHtml();
assert(html.includes('<strong>Grouping:</strong> publisher'));
assert(html.includes('Fixture 500'));assert(html.includes('<strong>Shown processes:</strong> 501'));
assert(html.includes('Verification Guide'));
""")

    def test_verification_report_keeps_review_rows_safety_and_escaping(self):
        self.run_process_report("""
state.processes[0].friendly_name='<script>fixture</script>';
const html=buildVerificationReportHtml();assert(html.includes('Fixture 500'));
assert(html.includes('&lt;script&gt;fixture&lt;/script&gt;'));assert(!html.includes('<script>fixture</script>'));
assert(html.includes('Verification Guide'));assert(html.includes('does not prove whether a program is safe or harmful'));
""")


if __name__=='__main__':
    unittest.main()
