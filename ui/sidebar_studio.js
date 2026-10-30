/* Offline Sidebar Studio controller. No requests, diagnostic collectors or credentials. */
const Studio = (() => {
    'use strict';
    const views = ['overview', 'scan', 'results', 'processes', 'installer', 'security', 'history', 'manual', 'about'];
    const resultViews = ['folders', 'files', 'types', 'tree', 'health'];
    const titles = {overview:'Overview', scan:'Scan', results:'Results', processes:'Processes',
        installer:'Installer Cache', security:'Security Check', history:'History', manual:'Manual / Help', about:'About'};
    const storageKey = 'disk-usage-studio-v1';
    const object = value => value && typeof value === 'object' && !Array.isArray(value);
    const rowsOf = value => Array.isArray(value) ? value.filter(object) : [];
    const text = value => String(value ?? '');
    const escape = value => text(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const recorded = value => value === undefined || value === null || value === '' ? 'Not recorded' : value;
    const bytes = row => typeof row.bytes === 'number' && Number.isFinite(row.bytes) && row.bytes >= 0 ? row.bytes : null;
    let ui = null;

    function validatePreferences(value) {
        const data = object(value) ? value : {};
        return {view:views.includes(data.view) ? data.view : 'overview',
            resultView:resultViews.includes(data.resultView) ? data.resultView : 'folders', collapsed:data.collapsed === true};
    }

    function readPreferences(storage) {
        try { return validatePreferences(JSON.parse(storage.getItem(storageKey))); }
        catch { return validatePreferences(null); }
    }

    function savePreferences(storage, value) {
        try { storage.setItem(storageKey, JSON.stringify(validatePreferences(value))); } catch { /* Optional storage. */ }
    }

    function pageRows(value, options = {}) {
        const pageSize = [25,50,100].includes(options.pageSize) ? options.pageSize : 25;
        const query = text(options.query).trim().toLocaleLowerCase();
        const rows = rowsOf(value).filter(row => !query || Object.values(row).some(v =>
            ['string','number'].includes(typeof v) && text(v).toLocaleLowerCase().includes(query)));
        rows.sort((a,b) => {
            if (options.sort === 'name-asc') return text(a.path ?? a.extension).localeCompare(text(b.path ?? b.extension));
            const av = bytes(a), bv = bytes(b);
            if (av === null) return bv === null ? 0 : 1;
            if (bv === null) return -1;
            return options.sort === 'bytes-asc' ? av-bv : bv-av;
        });
        const pages = Math.max(1, Math.ceil(rows.length / pageSize));
        const requested = Number.isInteger(options.page) ? options.page : 1;
        const page = Math.max(1, Math.min(pages, requested));
        return {rows:rows.slice((page-1)*pageSize,page*pageSize),total:rows.length,page,pages,pageSize};
    }

    function healthModel(record) {
        const result = object(record?.result) ? record.result : {};
        if (['cancelled','error','failed'].includes(record?.status)) return {level:'warning', title:'Partial scan results',
            message:`Scan ${record.status}. Recorded totals cover only the work completed.`, next_steps:'Review recorded errors and skipped paths before drawing conclusions.'};
        const health = object(result.scan_health) ? result.scan_health : {};
        const model = {level:['info','success','warning','error'].includes(health.level) ? health.level : 'info',
            title:health.title || 'No scan health recorded', message:health.message || 'Coverage is not recorded for this scan.',
            next_steps:health.next_steps || 'Run a new scan for current coverage details.'};
        if (Number(result.summary?.skipped_count) > 0 && model.level === 'success') {
            model.level = 'warning'; model.title = 'Skipped paths require review';
        }
        return model;
    }

    function overviewModel(record, history) {
        const result = object(record?.result) ? record.result : null;
        const summary = object(result?.summary) ? result.summary : {};
        return {hasRecord:Boolean(result), size:recorded(summary.total_size), files:recorded(summary.files_scanned),
            foldersCount:recorded(summary.folders_scanned), skipped:recorded(summary.skipped_count),
            folders:pageRows(result?.top_folders).rows.slice(0,5), recent:rowsOf(history).slice(0,5), health:healthModel(record)};
    }

    function completionNotice(record) {
        if (record.status === 'completed') {
            const health = healthModel(record);
            const complete = health.level === 'success' && record.result?.summary?.skipped_count === 0;
            return {type:complete ? 'success' : 'warning', title:complete ? 'Scan Completed' : 'Scan Completed - Review Coverage'};
        }
        return record.status === 'cancelled' ? {type:'warning',title:'Scan Cancelled'} : {type:'error',title:'Scan Failed'};
    }

    function addNotification(existing, value) {
        const item = {type:['info','success','warning','error'].includes(value.type) ? value.type : 'info',
            title:text(value.title), message:text(value.message), details:Array.isArray(value.details) ? value.details.map(text) : []};
        const identity = JSON.stringify(item);
        const list = [item, ...rowsOf(existing).filter(row => JSON.stringify(row) !== identity)];
        // Routine polling/copy messages cannot evict errors or incomplete-coverage warnings.
        let routine = Math.max(0, 50-list.filter(row => ['error','warning'].includes(row.type)).length);
        return list.filter(row => ['error','warning'].includes(row.type) || routine-- > 0);
    }

    function treeIdentity(record) {
        return JSON.stringify([text(record?.scan_id || record?.root || 'legacy'), text(record?.result?.tree_html)]);
    }

    function icon(name) {
        return `<svg class="icon" aria-hidden="true"><use href="#icon-${name}"></use></svg>`;
    }

    function metricHtml(label, value) {
        return `<div class="metric"><div class="label">${escape(label)}</div><div class="value">${escape(recorded(value))}</div></div>`;
    }

    function pathHtml(value) {
        const path = text(value) || 'Not recorded';
        return `<details class="path-detail"><summary title="${escape(path)}">${escape(path)}</summary><code>${escape(path)}</code></details>`;
    }

    function preferenceChanged() { savePreferences(ui.storage, ui.prefs); }

    function setDrawer(open, restoreFocus = true) {
        if (!ui) return;
        const narrow = ui.media.matches;
        ui.drawerOpen = Boolean(open && narrow);
        ui.doc.body.classList.toggle('sidebar-open', ui.drawerOpen);
        ui.el('drawerBackdrop').classList.toggle('hidden', !ui.drawerOpen);
        ui.el('openSidebar').setAttribute('aria-expanded', String(ui.drawerOpen));
        ui.el('sidebar').inert = narrow && !ui.drawerOpen;
        ui.el('appContent').inert = ui.drawerOpen;
        if (ui.drawerOpen) {
            ui.el('sidebar').setAttribute('role','dialog');
            ui.el('sidebar').setAttribute('aria-modal','true');
            ui.el('closeSidebar').focus();
        } else {
            ui.el('sidebar').removeAttribute('role');
            ui.el('sidebar').removeAttribute('aria-modal');
            if (restoreFocus && narrow) ui.el('openSidebar').focus();
        }
    }

    function toggleCollapse() {
        ui.prefs.collapsed = !ui.prefs.collapsed;
        applyCollapse(); preferenceChanged();
    }

    function applyCollapse() {
        ui.doc.body.classList.toggle('sidebar-collapsed', ui.prefs.collapsed);
        const button = ui.el('collapseSidebar');
        button.setAttribute('aria-expanded', String(!ui.prefs.collapsed));
        const label = ui.prefs.collapsed ? 'Expand sidebar' : 'Collapse sidebar';
        button.setAttribute('aria-label',label); button.title = label;
    }

    function navigate(requested, focus = false) {
        if (!ui) return 'overview';
        const view = views.includes(requested) ? requested : 'overview';
        ui.prefs.view = view;
        ui.doc.querySelectorAll('.tab').forEach(button => {
            const active = button.dataset.tab === view;
            button.classList.toggle('active',active);
            if (active) button.setAttribute('aria-current','page'); else button.removeAttribute('aria-current');
        });
        ui.doc.querySelectorAll('.tab-panel').forEach(panel => panel.classList.toggle('hidden', panel.id !== 'tab-'+view));
        ui.el('pageTitle').textContent = titles[view];
        setDrawer(false,false); preferenceChanged();
        if (view === 'results') selectResultView(ui.prefs.resultView);
        if (focus) ui.el('pageTitle').focus();
        return view;
    }

    function selectResultView(requested, focus = false) {
        const view = resultViews.includes(requested) ? requested : 'folders';
        ui.prefs.resultView = view;
        ui.doc.querySelectorAll('[data-result-view]').forEach(button => {
            const selected = button.dataset.resultView === view;
            button.setAttribute('aria-selected',String(selected)); button.tabIndex = selected ? 0 : -1;
        });
        resultViews.forEach(name => ui.el('result-'+name).classList.toggle('hidden',name !== view));
        if (ui.record) {
            if (view === 'tree') renderTree(ui.record);
            else if (view === 'health') renderTable('skipped');
            else renderTable(view);
        }
        preferenceChanged();
        if (focus) ui.el('result-tab-'+view).focus();
    }

    function renderOverview() {
        if (!ui) return;
        const model = overviewModel(ui.record,ui.history);
        ui.el('overviewMetrics').innerHTML = [metricHtml('Scanned size',model.size),metricHtml('Folders scanned',model.foldersCount),
            metricHtml('Files scanned',model.files),metricHtml('Skipped paths',model.skipped)].join('');
        ui.el('overviewResults').disabled = !model.hasRecord;
        ui.el('scanReviewResults').disabled = !model.hasRecord;
        ui.el('overviewRecordInfo').textContent = model.hasRecord
            ? `${recorded(ui.record.status)} · ${recorded(ui.record.completed_at || ui.record.started_at)} · ${recorded(ui.record.root)}` : 'No scan recorded';
        coverageStrip('overviewHealth',model.health,model.hasRecord);
        const largest = Math.max(1,...model.folders.map(row => bytes(row) || 0));
        ui.el('overviewFolders').innerHTML = model.folders.map(row =>
            `<div class="folder-bar-row"><div class="folder-bar-label"><span title="${escape(row.path)}">${escape(row.name || row.path)}</span><span>${escape(row.size || 'Not recorded')}</span></div><div class="folder-bar-track"><div class="folder-bar-fill" style="width:${((bytes(row)||0)/largest*100).toFixed(2)}%"></div></div></div>`
        ).join('') || '<p class="empty-state">No folder sizes recorded. Start a scan to record disk usage.</p>';
        ui.el('overviewHistoryRows').innerHTML = model.recent.map(row =>
            `<div class="recent-scan"><div><span class="scan-path" title="${escape(row.root)}">${escape(recorded(row.root))}</span><span class="scan-meta">${escape(recorded(row.started_at))} · ${escape(recorded(row.status))} · ${escape(recorded(row.total_size))}</span></div><button class="icon-button" data-studio-history="${escape(row.scan_id)}" aria-label="Open scan ${escape(row.started_at)}" title="Open scan">${icon('chevron-right')}</button></div>`
        ).join('') || '<p class="empty-state">No scans saved yet.</p>';
    }

    function coverageStrip(id, health, hasRecord) {
        const node = ui.el(id);
        node.className = 'coverage-strip '+(hasRecord ? health.level : 'info');
        node.innerHTML = `<span class="status-dot"></span><span>${escape(hasRecord ? health.title : 'No scan health recorded')}</span>${icon('chevron-right')}`;
        node.disabled = !hasRecord;
    }

    function renderHealth(result, record = ui?.record) {
        if (!ui) return;
        const health = healthModel(record || {result});
        const categories = rowsOf(Object.values(object(result.skip_categories) ? result.skip_categories : {}));
        ui.el('scanHealth').className = 'health-panel '+health.level;
        ui.el('scanHealth').innerHTML = `<h3>${escape(health.title)}</h3><p>${escape(health.message)}</p><p><strong>Next:</strong> ${escape(health.next_steps)}</p>`+
            `<details><summary>Skipped-path categories (${categories.length})</summary><div class="category-list">${categories.map(row => `<div class="category-item"><strong>${escape(row.label)}: ${escape(row.count)}</strong><p>${escape(row.explanation)}</p></div>`).join('') || '<p>No categories recorded.</p>'}</div></details>`;
        const count = result.summary?.skipped_count;
        ui.el('skippedSummary').textContent = `Skipped path details (${recorded(count)} total)`;
        ui.el('skippedTruncation').classList.toggle('hidden',!result.skipped_truncated);
        ui.el('skippedTruncation').textContent = 'Details are truncated in this saved record. Summary totals include additional skipped paths.';
        coverageStrip('resultHealthNotice',health,Boolean(record?.result));
    }

    function recordRows(kind) {
        const result = ui.record?.result || {};
        if (kind === 'skipped') return rowsOf(result.skipped_details).length ? rowsOf(result.skipped_details)
            : (Array.isArray(result.skipped) ? result.skipped.map(path => ({path,category_label:'Skipped'})) : []);
        return rowsOf(result[{folders:'top_folders',files:'biggest_files',types:'file_types'}[kind]]);
    }

    function renderTable(kind) {
        if (!ui) return;
        const setting = ui.tables[kind];
        const page = pageRows(recordRows(kind),setting);
        setting.page = page.page;
        const target = {folders:'topFolders',files:'biggestFiles',types:'fileTypes',skipped:'skippedRows'}[kind];
        const copy = path => `<button class="icon-button copy-button" data-copy-path="${escape(path)}" data-copy-label="result directory" title="Copy directory" aria-label="Copy directory ${escape(path)}">${icon('copy')}</button>`;
        const body = page.rows.map((row,index) => {
            const rank = (page.page-1)*page.pageSize+index+1;
            if (kind === 'types') return `<tr><td>${escape(recorded(row.extension))}</td><td>${escape(recorded(row.size))}</td><td>${escape(recorded(row.count))}</td></tr>`;
            if (kind === 'skipped') return `<tr><td>${escape(row.category_label || 'Skipped')}</td><td>${pathHtml(row.path)}<p>${escape(row.explanation || row.error || '')}</p></td></tr>`;
            const directory = kind === 'folders' ? row.path : directoryFromPath(row.path);
            return `<tr><td>${rank}</td><td>${escape(recorded(row.size))}</td><td>${escape(recorded(kind === 'folders' ? row.file_count : row.modified))}</td><td>${pathHtml(row.path)}</td><td>${directory ? copy(directory) : ''}</td></tr>`;
        }).join('');
        const columns = kind === 'types' ? 3 : kind === 'skipped' ? 2 : 5;
        ui.el(target).innerHTML = body || `<tr><td colspan="${columns}">${setting.query ? 'No matching rows.' : ui.record ? 'No rows recorded for this scan.' : 'No scan loaded.'}</td></tr>`;
        ui.el(kind+'PageInfo').textContent = page.total ? `${(page.page-1)*page.pageSize+1}-${Math.min(page.page*page.pageSize,page.total)} of ${page.total} · Page ${page.page}/${page.pages}` : '0 rows · Page 1/1';
        ui.el(kind+'Previous').disabled = page.page <= 1;
        ui.el(kind+'Next').disabled = page.page >= page.pages;
    }

    function renderRecord(record) {
        if (!object(record?.result)) throw new Error('The selected history record has no result data.');
        if (!ui) return;
        const changed = ui.record?.scan_id !== record.scan_id;
        ui.record = record;
        if (changed) Object.values(ui.tables).forEach(setting => { setting.page = 1; });
        const model = overviewModel(record,ui.history);
        ui.el('resultRecordInfo').innerHTML = `<span>${escape(recorded(record.status))} · ${escape(recorded(record.root))}</span>`+
            `<details><summary>Scan details</summary><p>Started: ${escape(recorded(record.started_at))} · Completed: ${escape(recorded(record.completed_at))}<br>Scan ID: ${escape(recorded(record.scan_id))}</p></details>`;
        ui.el('resultSummary').innerHTML = [metricHtml('Scanned size',model.size),metricHtml('Folders scanned',model.foldersCount),metricHtml('Files scanned',model.files),metricHtml('Skipped paths',model.skipped)].join('');
        renderHealth(record.result,record);
        selectResultView(ui.prefs.resultView);
        renderOverview();
    }

    function recordError(record, error) {
        if (!ui) return;
        ui.record = null;
        ui.el('resultRecordInfo').textContent = `Record could not be displayed: ${text(error?.message || error)}`;
        ui.el('resultSummary').innerHTML = '';
        ui.el('scanHealth').className = 'health-panel error';
        ui.el('scanHealth').textContent = 'Result display failed. Coverage and totals are unavailable.';
        ui.el('skippedSummary').textContent = 'Skipped path details unavailable';
        ui.el('skippedTruncation').classList.add('hidden');
        ui.el('treeView').textContent = 'No tree data shown.';
        ui.treeIdentity = null;
        Object.keys(ui.tables).forEach(renderTable);
        coverageStrip('resultHealthNotice',{level:'error',title:'Result could not be displayed'},true);
        renderOverview();
    }

    function renderTree(record) {
        const identity = treeIdentity(record);
        if (ui.treeIdentity === identity) return;
        const container = ui.el('treeView');
        const recordKey = text(record.scan_id || record.root || 'legacy');
        let choices = ui.treeStates.get(recordKey);
        if (!choices) {
            choices = new Map(); ui.treeStates.set(recordKey,choices);
            if (ui.treeStates.size > 5) ui.treeStates.delete(ui.treeStates.keys().next().value);
        }
        const previousScroll = container.scrollTop;
        const template = ui.doc.createElement('template');
        template.innerHTML = text(record.result.tree_html);
        // Only inert backend tree elements are copied; saved HTML cannot add handlers or remote assets.
        const allowed = new Set(['DETAILS','SUMMARY','DIV','SPAN']);
        const sanitize = node => {
            if (node.nodeType === 3) return ui.doc.createTextNode(node.textContent);
            if (node.nodeType !== 1 || !allowed.has(node.tagName)) return ui.doc.createTextNode('');
            const clean = ui.doc.createElement(node.tagName.toLowerCase());
            clean.className = [...node.classList].filter(name => /^tree-(node|leaf|children|name|size|files|path)$|^depth-\d{1,2}$/.test(name)).join(' ');
            if (node.tagName === 'DETAILS') clean.open = node.hasAttribute('open');
            node.childNodes.forEach(child => clean.appendChild(sanitize(child)));
            return clean;
        };
        const fragment = ui.doc.createDocumentFragment();
        template.content.childNodes.forEach(node => fragment.appendChild(sanitize(node)));
        container.replaceChildren(fragment);
        if (!container.textContent.trim()) container.textContent = 'No tree data recorded at these display thresholds.';
        container.querySelectorAll('details.tree-node').forEach((node,index) => {
            const path = node.querySelector('summary .tree-path')?.textContent || String(index);
            node.dataset.treeKey = path;
            if (choices.has(path)) node.open = choices.get(path);
        });
        ui.treeIdentity = identity; ui.treeRecordKey = recordKey;
        container.scrollTop = previousScroll;
    }

    function updateHistory(records) { if (ui) { ui.history = rowsOf(records); renderOverview(); } }

    function updateOperation(state, progress = null) {
        if (!ui) return;
        const busy = Boolean(state.scanActive || state.securityCheckActive);
        const label = state.isShuttingDown ? 'Shutting down' : state.scanActive ? 'Scan running' : state.securityCheckActive ? 'Security Check running' : 'Idle';
        ui.el('operationStatus').textContent = label;
        ui.el('operationStatus').classList.toggle('busy',busy);
        if (progress) ui.el('scanProgressMetrics').innerHTML = [metricHtml('Folders',progress.folders_scanned),metricHtml('Files',progress.files_scanned),metricHtml('Scanned size',progress.total_size),metricHtml('Skipped',progress.skipped_count)].join('');
    }

    function notificationHtml(item) {
        return `<div class="notification-item ${item.type}"><strong>${escape(item.title)}</strong><p>${escape(item.message)}</p>${item.details.length ? `<details><summary>Details</summary><p>${item.details.map(escape).join('<br>')}</p></details>` : ''}</div>`;
    }

    function notify(type, title, message, details = []) {
        if (!ui) return;
        const item = addNotification([],{type,title,message,details})[0];
        const key = JSON.stringify(item);
        if (key === ui.lastNotificationKey) return;
        ui.lastNotificationKey = key;
        const list = ui.el('notificationList');
        if (!ui.notificationNodes.has(key)) {
            if (!ui.notificationNodes.size) list.replaceChildren();
            ui.notifications = addNotification(ui.notifications,item);
            const entry = ui.doc.createElement('div');
            entry.innerHTML = notificationHtml(item);
            list.prepend(entry); ui.notificationNodes.set(key,entry);
            const retained = new Set(ui.notifications.map(row=>JSON.stringify(row)));
            for (const [known,node] of ui.notificationNodes) if (!retained.has(known)) { node.remove();ui.notificationNodes.delete(known); }
        }
        ui.el('notificationCount').textContent = String(ui.notifications.length);
        ui.el('notificationCount').classList.remove('hidden');
        const critical = ui.notifications.filter(row => ['error','warning'].includes(row.type)).length;
        ui.el('notificationToggle').setAttribute('aria-label',`Notifications: ${ui.notifications.length}, ${critical} warnings or errors`);
        const node = ui.el('actionAlert');
        if (ui.toastCritical && (!['error','warning'].includes(item.type) || node.contains(ui.doc.activeElement))) return;
        if (ui.toastKey === key && !node.classList.contains('hidden')) return;
        ui.toastKey = key;
        ui.win.clearTimeout(ui.toastTimer);
        ui.toastCritical = ['error','warning'].includes(item.type);
        node.className = 'action-alert '+item.type;
        node.setAttribute('role',item.type === 'error' ? 'alert' : 'status');
        node.setAttribute('aria-live',item.type === 'error' ? 'assertive' : 'polite');
        node.innerHTML = `<div class="alert-heading"><h2>${escape(item.title)}</h2><button class="icon-button" data-dismiss-alert aria-label="Dismiss notification" title="Dismiss notification">${icon('x')}</button></div><p>${escape(item.message)}</p>`+
            (item.details.length ? `<details><summary>Details</summary><p>${item.details.map(escape).join('<br>')}</p></details>` : '');
        if (!ui.toastCritical) ui.toastTimer = ui.win.setTimeout(()=>node.classList.add('hidden'),5000);
    }

    function showNotifications(open) {
        ui.el('notificationPanel').classList.toggle('hidden',!open);
        ui.el('notificationToggle').setAttribute('aria-expanded',String(open));
        (open ? ui.el('closeNotifications') : ui.el('notificationToggle')).focus();
    }

    function init(doc = document, win = window) {
        let storage; try { storage = win.localStorage; } catch { storage = null; }
        ui = {doc,win,storage,el:id=>doc.getElementById(id),prefs:readPreferences(storage),record:null,history:[],notifications:[],notificationNodes:new Map(),
            media:win.matchMedia('(max-width: 900px)'),drawerOpen:false,treeStates:new Map(),treeIdentity:null,treeRecordKey:null,
            tables:Object.fromEntries(['folders','files','types','skipped'].map(kind=>[kind,{page:1,pageSize:25,query:'',sort:'bytes-desc'}]))};
        applyCollapse(); setDrawer(false,false); navigate(ui.prefs.view); selectResultView(ui.prefs.resultView); renderOverview();
        ui.el('collapseSidebar').addEventListener('click',toggleCollapse);
        ui.el('openSidebar').addEventListener('click',()=>setDrawer(true));
        ui.el('closeSidebar').addEventListener('click',()=>setDrawer(false));
        ui.el('drawerBackdrop').addEventListener('click',()=>setDrawer(false));
        ui.media.addEventListener('change',()=>{ const wasOpen=ui.drawerOpen; setDrawer(false,false); if(wasOpen)ui.el('pageTitle').focus(); });
        ui.doc.querySelectorAll('[data-result-view]').forEach(button=>{
            button.addEventListener('click',()=>selectResultView(button.dataset.resultView));
            button.addEventListener('keydown',event=>{
                if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
                event.preventDefault();
                const index=resultViews.indexOf(button.dataset.resultView);
                const next=event.key==='Home' ? 0 : event.key==='End' ? resultViews.length-1 : (index+(event.key==='ArrowRight'?1:-1)+resultViews.length)%resultViews.length;
                selectResultView(resultViews[next],true);
            });
        });
        const filters={folders:'folderFilter',files:'fileFilter',types:'typeFilter',skipped:'skippedFilter'};
        Object.keys(ui.tables).forEach(kind=>{
            ui.el(filters[kind]).addEventListener('input',()=>{ui.tables[kind].query=ui.el(filters[kind]).value;ui.tables[kind].page=1;renderTable(kind);});
            ui.el(kind+'PageSize').addEventListener('change',()=>{ui.tables[kind].pageSize=Number(ui.el(kind+'PageSize').value);ui.tables[kind].page=1;renderTable(kind);});
            for(const [suffix,delta] of [['Previous',-1],['Next',1]])ui.el(kind+suffix).addEventListener('click',()=>{ui.tables[kind].page+=delta;renderTable(kind);});
            if(kind!=='skipped')ui.el(kind+'Sort').addEventListener('change',()=>{ui.tables[kind].sort=ui.el(kind+'Sort').value;ui.tables[kind].page=1;renderTable(kind);});
            renderTable(kind);
        });
        for(const id of ['overviewScan','resultsNewScan'])ui.el(id).addEventListener('click',()=>{showTab('scan');ui.el('rootPath').focus();});
        for(const id of ['overviewResults','scanReviewResults'])ui.el(id).addEventListener('click',()=>showTab('results'));
        ui.el('overviewHistory').addEventListener('click',()=>showTab('history'));
        ui.el('overviewHistoryRows').addEventListener('click',event=>{const button=event.target.closest('[data-studio-history]');if(button)openHistory(button.dataset.studioHistory);});
        ui.doc.querySelectorAll('[data-open-health]').forEach(button=>button.addEventListener('click',()=>{showTab('results');selectResultView('health',true);}));
        ui.el('treeView').addEventListener('toggle',event=>{
            const key=event.target.dataset.treeKey;
            if(key&&ui.treeRecordKey)ui.treeStates.get(ui.treeRecordKey)?.set(key,event.target.open);
        },true);
        ui.el('notificationToggle').addEventListener('click',()=>showNotifications(ui.el('notificationPanel').classList.contains('hidden')));
        ui.el('closeNotifications').addEventListener('click',()=>showNotifications(false));
        ui.el('actionAlert').addEventListener('click',event=>{if(event.target.closest('[data-dismiss-alert]')){ui.el('actionAlert').classList.add('hidden');ui.toastCritical=false;ui.el('notificationToggle').focus();}});
        ui.doc.addEventListener('keydown',event=>{
            if(ui.drawerOpen){
                if(event.key==='Escape'){event.preventDefault();setDrawer(false);return;}
                if(event.key==='Tab'){
                    const buttons=[...ui.el('sidebar').querySelectorAll('button:not([disabled]),a[href]')].filter(node=>node.offsetParent!==null);
                    const first=buttons[0],last=buttons.at(-1);
                    if(event.shiftKey&&doc.activeElement===first){event.preventDefault();last.focus();}
                    else if(!event.shiftKey&&doc.activeElement===last){event.preventDefault();first.focus();}
                }
            }else if(event.key==='Escape'&&!ui.el('notificationPanel').classList.contains('hidden'))showNotifications(false);
        });
    }

    return {validatePreferences,readPreferences,savePreferences,pageRows,healthModel,overviewModel,completionNotice,addNotification,treeIdentity,
        init,navigate,toggleCollapse,setDrawer,selectResultView,renderOverview,renderRecord,recordError,renderHealth,renderTable,
        renderTree,updateHistory,updateOperation,notify,pathHtml};
})();
if (typeof module !== 'undefined' && module.exports) module.exports = Studio;
