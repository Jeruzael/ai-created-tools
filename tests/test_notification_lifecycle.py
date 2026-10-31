import unittest
import test_sidebar_studio as fixtures


class NotificationLifecycleTests(unittest.TestCase):
    run_js = fixtures.StudioControllerTests.run_js
    run_dom = fixtures.StudioControllerTests.run_dom
    core_functions = fixtures.StudioControllerTests.core_functions
    # Reuse the actual controller/DOM ports, not an imitation notification model.
    def test_fifteen_read_new_and_duplicate_lifecycle(self):
        self.run_dom("""
for(let i=0;i<15;i++)Studio.notify('warning','Event '+i,'Fixture',['Details']);
assert.equal(f.element('notificationCount').textContent,'15');
f.element('notificationToggle').dispatch('click');
assert(f.element('notificationCount').classList.contains('hidden'));
assert.equal(Studio.notificationState().unread,0);
f.element('closeNotifications').dispatch('click');f.element('notificationToggle').dispatch('click');
assert.equal(Studio.notificationState().unread,0);
assert.equal(Studio.notificationState().entries.length,15);
f.element('closeNotifications').dispatch('click');
Studio.notify('error','New failure','Fixture',['New details']);
assert.equal(f.element('notificationCount').textContent,'1');
for(let i=0;i<15;i++)Studio.notify('error','New failure','Fixture',['New details']);
assert.equal(Studio.notificationState().unread,1);assert.equal(Studio.notificationState().entries.length,16);
assert(f.element('notificationList').innerHTML.includes('Event 0'));
""")

    def test_messages_arriving_in_open_panel_are_read(self):
        self.run_dom("""
f.element('notificationToggle').dispatch('click');Studio.notify('error','Visible failure','Fixture');
assert.equal(Studio.notificationState().unread,0);
assert(f.element('notificationCount').classList.contains('hidden'));
f.element('closeNotifications').dispatch('click');assert.equal(Studio.notificationState().unread,0);
""")

    def test_mark_read_and_clear_routine_keep_critical_history(self):
        self.run_dom("""
Studio.notify('warning','Critical','Fixture');Studio.notify('success','Export complete','Fixture');
Studio.markNotificationsRead();assert.equal(Studio.notificationState().unread,0);
Studio.clearRoutineNotifications();
assert.equal(Studio.notificationState().entries.length,1);
assert.equal(Studio.notificationState().entries[0].type,'warning');
assert(f.element('notificationList').innerHTML.includes('Critical'));
""")

    def test_dismissed_poll_message_is_not_recreated_as_unread(self):
        self.run_dom("""
Studio.notify('error','Offline','Fixture');const id=Studio.notificationState().entries[0].id;
Studio.dismissNotification(id);assert.equal(Studio.notificationState().unread,0);
Studio.notify('info','Another routine','Fixture');Studio.notify('error','Offline','Fixture');
assert(!Studio.notificationState().entries.some(n=>n.title==='Offline'));
""")

    def test_navigation_and_detail_loading_do_not_increment_unread(self):
        self.run_dom("""
Studio.notify('info','Manual Opened','Fixture');Studio.notify('success','Process Details Loaded','Fixture');
assert.equal(Studio.notificationState().unread,0);
Studio.notify('success','Scan Completed','Fixture');assert.equal(Studio.notificationState().unread,1);
""")

    def test_event_id_distinguishes_genuine_operations_from_poll_repeats(self):
        self.run_dom("""
Studio.notify('success','Scan Completed','Same fixture',[],{eventId:'scan:one:completed'});
Studio.markNotificationsRead();
Studio.notify('success','Scan Completed','Same fixture',[],{eventId:'scan:one:completed'});
assert.equal(Studio.notificationState().unread,0);
Studio.notify('success','Scan Completed','Same fixture',[],{eventId:'scan:two:completed'});
assert.equal(Studio.notificationState().unread,1);assert.equal(Studio.notificationState().entries.length,2);
""")

    def test_later_manual_failure_is_new_after_read_dismiss_and_recovery(self):
        core=self.core_functions('refreshProcesses','showActionAlert','asArray')
        self.run_dom("""
global.state={processes:[]};let failing=true;
global.api=async()=>{if(failing)throw Error('Fixture offline');return {processes:[]};};
global.updatePublisherFilterOptions=()=>{};global.updateReviewFilterOptions=()=>{};
global.ProcessWorkspace={setLoading(){},setError(){},onSnapshot(){}};
"""+core+"""
(async()=>{
 await refreshProcesses();assert.equal(Studio.notificationState().unread,1);
 Studio.markNotificationsRead();Studio.dismissNotification(Studio.notificationState().entries[0].id);
 failing=false;await refreshProcesses();assert.equal(Studio.notificationState().entries.length,0);
 failing=true;await refreshProcesses();
 assert.equal(Studio.notificationState().unread,1);assert.equal(Studio.notificationState().entries.length,1);
})().catch(error=>{console.error(error);process.exitCode=1;});
""")

    def test_action_identities_are_per_attempt_while_poll_identities_stay_stable(self):
        self.run_dom("""
const first=Studio.actionNotifier(),second=Studio.actionNotifier();
first('error','Action failed','Same fixture');Studio.markNotificationsRead();
first('error','Action failed','Same fixture');assert.equal(Studio.notificationState().unread,0);
second('error','Action failed','Same fixture');assert.equal(Studio.notificationState().unread,1);
Studio.notify('error','Poll failed','Same fixture',[],{eventId:'poll:fixture:offline'});Studio.markNotificationsRead();
Studio.notify('error','Poll failed','Same fixture',[],{eventId:'poll:fixture:offline'});assert.equal(Studio.notificationState().unread,0);
""")
