/* Process Workspace sidecar, embedded after the core bridge and before its delegates run.
 * init({doc,win,readState,api,visibleProcesses,groupProcesses,publisherLabel,needsReview,
 *       reviewReasons,formatBytes,notify,copyText}) binds ONLY new presentation controls.
 * Core owns existing filters/row events, refresh/export actions and data-open-process-help.
 * renderProcesses -> render(); showProcessDetail(pid) -> open(pid, optionalOpener).
 * After a successful collection/state assignment call onSnapshot() ONCE, not on polling,
 * filtering, sorting or detail loading. Navigation away calls hide().
 * copyText(text) may return a promise; notify(type,title,message) is optional/error-only.
 * No storage, collectors, fetch, scoring or app-state writes occur here.
 *
 * New static IDs: processWorkspace, processStatus, processTable, processTableScroll,
 * processPageSize, processPageInfo, processPrevious, processNext, processSort, processDrawerBackdrop,
 * processDrawer, processDrawerClose, processDrawerTitle, processDrawerMeta,
 * processDetailStatus, processTabOverview/Signature/Technical,
 * processDetailOverview/Signature/Technical, process-icon-refresh/download.
 * Dynamic: processCommand, processCommandToggle.
 * New data ports: data-process-sort, data-process-group, data-process-signature,
 * data-process-tab, data-process-copy; parent handles data-open-process-help.
 */
const ProcessWorkspace = (() => {
    'use strict';
    let bridge, doc, win;
    let page = 0, pageSize = 25, sortKey = 'program', descending = false, fingerprint = null;
    let selectedPid = null, openerRef = null, detail = null, activeTab = 'overview', expanded = false;
    let loading = false, listError = '', detailMessage = '', detailLoading = false;
    let requestToken = 0, revision = 0, isolated = [], bodyOverflow = '';
    const cache = new Map(), pending = new Map(), bindings = [];
    const tabNames = ['overview', 'signature', 'technical'];
    const tabSuffix = {overview: 'Overview', signature: 'Signature', technical: 'Technical'};
    const escape = value => String(value ?? '').replace(/[&<>"']/g,
        char => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'})[char]);
    const array = value => Array.isArray(value) ? value : [];
    const present = value => value !== undefined && value !== null && value !== '';
    const text = value => present(value) ? String(value) : 'Unavailable';
    const $ = id => doc.getElementById(id);
    const snapshot = () => array(bridge.readState().processes);
    const isOpen = () => selectedPid !== null && !$('processDrawer').hidden;
    const number = value => present(value) && Number.isFinite(Number(value)) && Number(value) >= 0 ? Number(value) : null;
    const memory = p => number(p.memory_bytes) === null ? 'Unavailable' : bridge.formatBytes(Number(p.memory_bytes));
    const name = p => p.friendly_name || p.name || 'Unknown process';
    const reasons = p => array(bridge.reviewReasons(p));
    const signature = p => p.signature && typeof p.signature === 'object' ? p.signature : {};
    const identityUnavailable = 'Process-instance identity unavailable. Refresh the process snapshot and reopen details.';
    const knownSignature = p => signature(cachedDetail(p) || p).status || 'Unavailable';

    function processIdentity(expected, actual) {
        if (!expected || !actual || String(expected.pid) !== String(actual.pid)) return 'mismatch';
        let matched = false;
        for (const key of ['started_at', 'executable_path', 'name']) {
            if (!present(expected[key]) || !present(actual[key])) continue;
            const normalize = value => key === 'started_at' ? String(value) : String(value).replace(/\//g, '\\').toLowerCase();
            if (normalize(expected[key]) !== normalize(actual[key])) return 'mismatch';
            if (key !== 'name') matched = true;
        }
        // Names can expose a contradiction, but cannot identify a process instance alone.
        return matched ? 'matched' : 'unknown';
    }

    function cachedDetail(p) {
        if (!p) return null;
        const cached = cache.get(String(p.pid));
        return processIdentity(p, cached) === 'matched' ? cached : null;
    }

    function bind(element, type, handler) {
        element.addEventListener(type, handler);
        bindings.push([element, type, handler]);
    }

    function init(options) {
        if (doc && bridge) close(false);
        bindings.splice(0).forEach(([element, type, handler]) => element.removeEventListener(type, handler));
        bridge = options; doc = options.doc; win = options.win;
        page = 0; pageSize = 25; sortKey = 'program'; descending = false; fingerprint = null;
        loading = false; listError = ''; selectedPid = null; detail = null;
        cache.clear(); pending.clear(); revision += 1; requestToken += 1;
        $('processPageSize').value = '25';
        bind($('processSort'), 'change', () => {
            const [key, direction] = $('processSort').value.split('-');
            if (['program', 'publisher', 'pid', 'memory', 'review', 'signature'].includes(key) &&
                ['asc', 'desc'].includes(direction)) { sortKey = key; descending = direction === 'desc'; }
            render();
        });
        doc.querySelectorAll('[data-process-sort]').forEach(button => bind(button, 'click', () => {
            const key = button.dataset.processSort;
            if (key === sortKey) descending = !descending;
            else { sortKey = key; descending = key === 'memory' || key === 'review'; }
            render();
        }));
        bind($('processPageSize'), 'change', () => {
            const size = Number($('processPageSize').value);
            if (![25, 50, 100].includes(size)) { $('processPageSize').value = String(pageSize); return; }
            page = Math.floor(page * pageSize / size); pageSize = size; render();
        });
        bind($('processPrevious'), 'click', () => { if (page > 0) { page -= 1; render(); } });
        bind($('processNext'), 'click', () => { page += 1; render(); });
        bind($('processDrawerClose'), 'click', () => close());
        bind($('processDrawerBackdrop'), 'click', () => close());
        doc.querySelectorAll('[data-process-tab]').forEach(button => {
            bind(button, 'click', () => setTab(button.dataset.processTab));
            bind(button, 'keydown', event => {
                let index = tabNames.indexOf(button.dataset.processTab);
                if (event.key === 'ArrowRight') index = (index + 1) % tabNames.length;
                else if (event.key === 'ArrowLeft') index = (index + tabNames.length - 1) % tabNames.length;
                else if (event.key === 'Home') index = 0;
                else if (event.key === 'End') index = tabNames.length - 1;
                else return;
                event.preventDefault(); setTab(tabNames[index]); $('processTab' + tabSuffix[tabNames[index]]).focus();
            });
        });
        bind($('processDetail'), 'click', event => {
            const copy = event.target.closest('[data-process-copy]');
            if (copy && !copy.disabled) { copyEvidence(copy.dataset.processCopy); return; }
            if (event.target.closest('#processCommandToggle')) {
                expanded = !expanded; applyCommandState();
            }
        });
        bind(doc, 'keydown', trapKeys);
        bind(doc, 'focusin', event => {
            if (isOpen() && !$('processDrawer').contains(event.target)) $('processDrawerClose').focus();
        });
        return ProcessWorkspace;
    }

    function filterFingerprint() {
        return JSON.stringify(['processFilter', 'processPublisherFilter', 'processGroupBy', 'processReviewFilter']
            .map(id => $(id).value).concat($('needsReviewOnly').checked));
    }

    function ordered(processes, positions) {
        const value = p => {
            if (sortKey === 'memory') return number(p.memory_bytes);
            if (sortKey === 'pid') return number(p.pid);
            if (sortKey === 'publisher') return bridge.publisherLabel(p);
            if (sortKey === 'review') return bridge.needsReview(p) ? reasons(p).length + 1 : 0;
            if (sortKey === 'signature') return knownSignature(p);
            return name(p);
        };
        return processes.slice().sort((a, b) => {
            const left = value(a), right = value(b);
            if (left === null && right !== null) return 1;
            if (right === null && left !== null) return -1;
            const compared = typeof left === 'number' && typeof right === 'number' ? left - right :
                String(left ?? '').localeCompare(String(right ?? ''));
            return (descending ? -compared : compared) || positions.get(String(a.pid)) - positions.get(String(b.pid));
        });
    }

    function rowHtml(p) {
        const pid = escape(p.pid), review = bridge.needsReview(p), reviewText = reasons(p).join('; ');
        return `<tr class="process-row" tabindex="0" data-pid="${pid}" aria-label="${escape(name(p))}, PID ${pid}">
            <td><strong>${escape(name(p))}</strong><span class="process-executable">${escape(p.name || 'Executable name unavailable')}</span><code class="process-path">${escape(p.executable_path || 'Executable path unavailable')}</code></td>
            <td>${escape(bridge.publisherLabel(p))}</td><td class="process-number">${pid}</td>
            <td class="process-number">${escape(memory(p))}</td>
            <td><span class="process-review ${review ? 'needs-review' : ''}" title="${escape(reviewText || 'No local review reason recorded; not a safety verdict')}">${review ? 'Needs review' : 'No review flags'}</span>${reviewText ? `<span class="process-review-reasons">${escape(reviewText)}</span>` : ''}</td>
            <td data-process-signature>${escape(knownSignature(p))}</td>
            <td><button type="button" class="small-action" data-pid="${pid}" aria-controls="processDrawer" aria-expanded="false" aria-label="Details for ${escape(name(p))}, PID ${pid}">Details</button></td></tr>`;
    }

    function render() {
        const scroll = $('processTableScroll'), top = scroll.scrollTop, left = scroll.scrollLeft;
        const active = doc.activeElement, activeRow = active?.closest?.('tr[data-pid]');
        const restorePid = activeRow && $('processRows').contains(activeRow) ? activeRow.dataset.pid : null;
        const nextFingerprint = filterFingerprint();
        if (fingerprint !== null && fingerprint !== nextFingerprint) page = 0;
        fingerprint = nextFingerprint;
        const visible = array(bridge.visibleProcesses()), all = snapshot();
        const positions = new Map(visible.map((p, index) => [String(p.pid), index]));
        const mode = $('processGroupBy').value;
        let groups;
        if (mode === 'none' || !mode) groups = [{name: null, processes: ordered(visible, positions)}];
        else groups = array(bridge.groupProcesses(visible.slice(), mode === 'uncategorized' ? 'publisher' : mode))
            .map(group => ({...group, processes: ordered(array(group.processes), positions)}));
        const count = groups.reduce((sum, group) => sum + group.processes.length, 0);
        const pages = Math.max(1, Math.ceil(count / pageSize));
        page = Math.min(Math.max(0, page), pages - 1);
        const start = page * pageSize, end = Math.min(start + pageSize, count);
        let offset = 0, html = '';
        for (const group of groups) {
            const groupEnd = offset + group.processes.length;
            const slice = group.processes.slice(Math.max(0, start - offset), Math.max(0, end - offset));
            if (slice.length) {
                if (group.name !== null) html += `<tr class="process-group-header" data-process-group><th scope="rowgroup" colspan="7">${escape(group.name)} <span>${group.processes.length} processes | ${escape(bridge.formatBytes(group.totalMemory))}</span></th></tr>`;
                html += slice.map(rowHtml).join('');
            }
            offset = groupEnd;
            if (offset >= end) break;
        }
        const empty = listError || (loading ? 'Loading process snapshot...' : all.length ? 'No processes match the current filters.' : 'No process snapshot available. Refresh to collect running programs.');
        $('processRows').innerHTML = html || `<tr><td colspan="7" class="process-empty">${escape(empty)}</td></tr>`;
        $('processPrevious').disabled = page === 0;
        $('processNext').disabled = page >= pages - 1;
        $('processPageInfo').textContent = count ? `Page ${page + 1} of ${pages} | ${start + 1}-${end} of ${count}` : 'No rows';
        const measured = all.filter(p => number(p.memory_bytes) !== null);
        const totalMemory = measured.reduce((sum, p) => sum + Number(p.memory_bytes), 0);
        const metrics = [['Snapshot processes', all.length], ['Needs review', all.filter(bridge.needsReview).length],
            ['Measured memory', measured.length ? bridge.formatBytes(totalMemory) : 'Unavailable'],
            ['Publisher groups', new Set(all.map(bridge.publisherLabel)).size]];
        $('processSummary').innerHTML = metrics.map(([label, value]) => `<div><span>${escape(label)}</span><strong>${escape(value)}</strong></div>`).join('');
        const partial = all.some(p => !p.executable_path || number(p.memory_bytes) === null);
        $('processStatus').textContent = listError ? `Refresh unavailable: ${listError}${all.length ? ' Showing the last snapshot.' : ''}` :
            loading ? 'Refreshing process snapshot...' :
            all.length ? `${visible.length} shown of ${all.length} snapshot processes.${partial ? ' Partial data: some executable paths or memory measurements are unavailable.' : ''}` :
            'No process snapshot available. Refresh to collect running programs.';
        scroll.setAttribute('aria-busy', String(loading));
        doc.querySelectorAll('[data-process-sort]').forEach(button => {
            const selected = button.dataset.processSort === sortKey;
            button.closest('th').setAttribute('aria-sort', selected ? descending ? 'descending' : 'ascending' : 'none');
        });
        $('processSort').value = sortKey + (descending ? '-desc' : '-asc');
        updateSelection();
        if (restorePid !== null && !active.isConnected && !isOpen()) {
            const row = findRow(restorePid);
            focus(row ? active.tagName === 'BUTTON' ? row.querySelector('button') : row : $('processFilter'));
        }
        scroll.scrollTop = top; scroll.scrollLeft = left;
    }

    function findRow(pid) {
        return Array.from($('processRows').querySelectorAll('tr[data-pid]')).find(row => row.dataset.pid === String(pid));
    }

    function updateSelection() {
        const processes = new Map(snapshot().map(p => [String(p.pid), p]));
        $('processRows').querySelectorAll('tr[data-pid]').forEach(row => {
            const selected = isOpen() && row.dataset.pid === selectedPid;
            row.classList.toggle('selected', selected);
            if (selected) row.setAttribute('aria-current', 'true'); else row.removeAttribute('aria-current');
            row.querySelector('button').setAttribute('aria-expanded', String(selected));
            const p = processes.get(row.dataset.pid);
            row.querySelector('[data-process-signature]').textContent = p ? knownSignature(p) : 'Unavailable';
        });
    }

    function focus(element) {
        if (element && element.isConnected && !element.disabled) element.focus({preventScroll: true});
    }

    function isolateBackground() {
        if (isolated.length) return;
        let branch = $('processDrawer');
        while (branch && branch !== doc.body) {
            const parent = branch.parentElement;
            if (!parent) break;
            Array.from(parent.children).forEach(element => {
                if (element !== branch && element !== $('processDrawerBackdrop')) {
                    isolated.push([element, element.inert]); element.inert = true;
                }
            });
            branch = parent;
        }
        bodyOverflow = doc.body.style.overflow; doc.body.style.overflow = 'hidden';
    }

    function releaseBackground() {
        isolated.splice(0).forEach(([element, previous]) => { element.inert = previous; });
        doc.body.style.overflow = bodyOverflow || '';
    }

    function setTab(tab) {
        if (!tabNames.includes(tab)) return;
        activeTab = tab;
        tabNames.forEach(name => {
            const selected = name === tab, suffix = tabSuffix[name];
            $('processTab' + suffix).setAttribute('aria-selected', String(selected));
            $('processTab' + suffix).tabIndex = selected ? 0 : -1;
            $('processDetail' + suffix).hidden = !selected;
        });
    }

    const field = (label, value, code = false, controls = '') => `<div class="process-evidence-field"><div class="process-field-heading"><dt>${escape(label)}</dt>${controls}</div><dd>${code ? '<code>' : ''}${escape(text(value))}${code ? '</code>' : ''}</dd></div>`;
    const copyButton = (key, label, enabled) => `<button type="button" class="icon-button" data-process-copy="${key}" aria-label="Copy ${label}" title="Copy ${label}"${enabled ? '' : ' disabled'}><svg class="icon" aria-hidden="true"><use href="#icon-copy"></use></svg></button>`;

    function renderDetail() {
        const scroll = $('processDetail'), top = scroll.scrollTop;
        const active = doc.activeElement;
        const p = detail || snapshot().find(p => String(p.pid) === selectedPid) || {pid: selectedPid};
        const sig = detail ? signature(detail) : {}, review = reasons(p), indicators = array(p.risk_indicators);
        $('processDrawerTitle').textContent = name(p);
        $('processDrawerMeta').textContent = `PID ${text(p.pid)} | ${detail?.collected_at ? 'Collected ' + detail.collected_at : 'Local snapshot evidence'}`;
        $('processDetailStatus').textContent = detailMessage;
        scroll.setAttribute('aria-busy', String(detailLoading));
        $('processDetailOverview').innerHTML = `<dl class="process-evidence">${field('Program', name(p))}${field('Executable', p.name)}${field('PID', p.pid)}${field('Parent PID', p.parent_pid)}${field('Publisher', bridge.publisherLabel(p))}${field('Memory', memory(p))}${field('Executable path', p.executable_path, true, copyButton('path', 'executable path', !!detail?.executable_path))}</dl>
            <h4>${bridge.needsReview(p) ? 'Needs review' : 'No local review flags recorded'}</h4>
            <ul class="process-reasons">${review.length ? review.map(reason => `<li>${escape(reason)}</li>`).join('') : '<li>No review reason was recorded in this snapshot.</li>'}</ul>
            ${indicators.length ? `<ul class="process-indicators">${indicators.map(indicator => `<li>${escape(indicator.label || 'Indicator unavailable')} (${escape(indicator.level || 'level unavailable')})</li>`).join('')}</ul>` : ''}
            <p class="process-safety-note">Review indicators identify evidence to verify, not malware. Missing flags or a familiar publisher do not establish safety.</p>`;
        $('processDetailSignature').innerHTML = `<dl class="process-evidence">${field('Authenticode status', sig.status)}${field('Signer / publisher', sig.publisher)}
            ${field('Verification availability', !detail || !sig.status || sig.status === 'Unavailable' ? 'Unavailable' : sig.error ? 'Limited; see verification error' : 'Result recorded')}
            ${field('Verification error', sig.error || (sig.status && sig.status !== 'Unavailable' ? 'None reported' : 'Verification evidence unavailable'))}
            ${field('SHA-256', detail?.sha256, true, copyButton('hash', 'SHA-256', !!detail?.sha256))}
            ${field('Hash availability / error', detail?.hash_error || (detail?.sha256 ? 'Hash recorded' : 'Unavailable'))}</dl>
            <p class="process-safety-note">A valid signature does not prove a file is safe. An unsigned file is not automatically malicious. Verify the publisher, path and context.</p>`;
        $('processDetailTechnical').innerHTML = `<dl class="process-evidence">${field('Full executable path', p.executable_path, true, copyButton('path', 'executable path', !!detail?.executable_path))}
            <div class="process-evidence-field"><div class="process-field-heading"><dt>Command line</dt><div class="process-field-actions">${copyButton('command', 'command line', !!detail?.command_line)}<button id="processCommandToggle" type="button" aria-controls="processCommand" aria-expanded="false"${detail?.command_line ? '' : ' disabled'}>Expand</button></div></div><dd><code id="processCommand" class="process-command collapsed">${escape(text(detail?.command_line))}</code></dd></div>
            ${field('Original filename', p.original_filename || sig.original_filename)}${field('File description', p.file_description || sig.file_description)}
            ${field('Company metadata', p.company_name || sig.company_name)}${field('Product', p.product_name || sig.product_name)}
            ${field('Parent name', p.parent_name)}${field('Parent PID', p.parent_pid)}${field('Started at', p.started_at)}${field('Collected at', detail?.collected_at)}</dl>`;
        applyCommandState(); setTab(activeTab);
        if (active && !active.isConnected && isOpen()) focus($('processDrawerClose'));
        scroll.scrollTop = top;
    }

    function applyCommandState() {
        const button = $('processCommandToggle'), command = $('processCommand');
        if (!button || !command) return;
        button.setAttribute('aria-expanded', String(expanded)); button.textContent = expanded ? 'Collapse' : 'Expand';
        command.classList.toggle('collapsed', !expanded);
    }

    async function copyEvidence(key) {
        const value = detail && ({path: detail.executable_path, hash: detail.sha256, command: detail.command_line})[key];
        if (!value) return;
        const token = requestToken;
        try {
            if (typeof bridge.copyText !== 'function') throw Error('Clipboard unavailable');
            await bridge.copyText(String(value));
            if (token === requestToken && isOpen()) $('processDetailStatus').textContent = 'Copied.';
        } catch (_) {
            if (token !== requestToken || !isOpen()) return;
            $('processDetailStatus').textContent = 'Copy unavailable. The clipboard could not be accessed.';
            if (typeof bridge.notify === 'function') bridge.notify('error', 'Copy unavailable', 'The clipboard could not be accessed.');
        }
    }

    function detailsRequest(pid) {
        const expected = snapshot().find(p => String(p.pid) === pid);
        const cached = cachedDetail(expected);
        if (cached) return Promise.resolve({process: cached, message: ''});
        if (pending.has(pid)) return pending.get(pid);
        const version = revision;
        const identity = expected && {...expected};
        const request = (async () => {
            const response = await bridge.api('/api/processes/' + encodeURIComponent(pid));
            const p = response?.process;
            if (!p || typeof p !== 'object' || String(p.pid) !== pid) throw Error('No matching process evidence was returned.');
            const match = processIdentity(identity, p);
            if (match === 'mismatch') throw Error('Returned evidence does not match the snapshot process instance. The PID may have been reused.');
            if (match === 'unknown') {
                const sig = signature(p);
                if (!present(identity.name) || !present(p.name) || p.executable_path || p.sha256 ||
                    (sig.status && sig.status !== 'Unavailable')) throw Error(identityUnavailable);
                // Preserve protected-path availability errors, not unconfirmed process/file evidence.
                return {process: {...identity, executable_path: '', command_line: null, sha256: null,
                    signature: {status: 'Unavailable', error: sig.error}, hash_error: p.hash_error}, message: identityUnavailable};
            }
            if (version === revision) cache.set(pid, p);
            return {process: p, message: ''};
        })();
        pending.set(pid, request);
        const cleanup = () => { if (pending.get(pid) === request) pending.delete(pid); };
        request.then(cleanup, cleanup);
        return request;
    }

    async function open(pid, opener) {
        if (pid === null || pid === undefined || String(pid) === '') return;
        pid = String(pid);
        const wasOpen = isOpen(), changed = selectedPid !== pid;
        if (opener && !$('processDrawer').contains(opener)) openerRef = opener;
        else if (!wasOpen) openerRef = doc.activeElement === doc.body ? null : doc.activeElement;
        selectedPid = pid;
        const token = ++requestToken;
        if (changed || !wasOpen) { activeTab = 'overview'; expanded = false; $('processDetail').scrollTop = 0; }
        $('processDrawer').hidden = false; $('processDrawerBackdrop').hidden = false;
        isolateBackground(); updateSelection();
        const cached = cachedDetail(snapshot().find(p => String(p.pid) === pid));
        if (cached) {
            if (changed || !wasOpen || detail !== cached) {
                detail = cached; detailMessage = ''; detailLoading = false; renderDetail();
            }
            if (!wasOpen) focus($('processDrawerClose'));
            return;
        }
        detail = null; detailMessage = 'Loading local process details...'; detailLoading = true; renderDetail();
        if (!wasOpen) focus($('processDrawerClose'));
        try {
            const result = await detailsRequest(pid);
            if (token !== requestToken || !isOpen() || selectedPid !== pid) return;
            detail = result.process; detailLoading = false; detailMessage = result.message; renderDetail(); updateSelection();
        } catch (error) {
            if (token !== requestToken || !isOpen() || selectedPid !== pid) return;
            detail = null; detailLoading = false;
            detailMessage = `Process details unavailable: ${error?.message || 'No detail evidence returned.'} The process may have terminated or access may be restricted. Refresh the process snapshot and reopen details.`;
            renderDetail();
        }
    }

    function close(restoreFocus = true) {
        const pid = selectedPid, wasOpen = isOpen();
        requestToken += 1; selectedPid = null; detail = null; detailLoading = false;
        $('processDrawer').hidden = true; $('processDrawerBackdrop').hidden = true;
        if (wasOpen) releaseBackground();
        updateSelection();
        if (wasOpen && restoreFocus) {
            const row = findRow(pid);
            focus(openerRef?.isConnected && !openerRef.disabled ? openerRef : row?.querySelector('button') || $('processFilter'));
        }
        openerRef = null;
    }

    function onSnapshot() {
        revision += 1; requestToken += 1; cache.clear(); pending.clear(); loading = false; listError = '';
        render();
        if (!isOpen()) return Promise.resolve();
        if (!snapshot().some(p => String(p.pid) === selectedPid)) {
            detail = null; detailLoading = false;
            detailMessage = 'This PID is no longer in the refreshed snapshot. The process may have terminated or may not be visible. Signature and hash evidence are unavailable for this selection.';
            renderDetail(); return Promise.resolve();
        }
        return open(selectedPid);
    }

    function trapKeys(event) {
        if (!isOpen()) return;
        if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); close(); return; }
        if (event.key !== 'Tab') return;
        const drawer = $('processDrawer');
        const controls = Array.from(drawer.querySelectorAll('button, [href], input, select, textarea, [tabindex]'))
            .filter(element => {
                if (element.disabled || element.tabIndex < 0) return false;
                for (let ancestor = element; ancestor && ancestor !== drawer; ancestor = ancestor.parentElement)
                    if (ancestor.hidden || ancestor.inert) return false;
                return true;
            });
        const first = controls[0] || drawer, last = controls[controls.length - 1] || drawer;
        if (!drawer.contains(doc.activeElement) || doc.activeElement === drawer ||
            (!event.shiftKey && doc.activeElement === last) || (event.shiftKey && doc.activeElement === first)) {
            event.preventDefault(); focus(event.shiftKey ? last : first);
        }
    }

    function setLoading(value = true) { loading = Boolean(value); if (loading) listError = ''; render(); }
    function setError(error) { loading = false; listError = error ? String(error.message || error) : ''; render(); }
    function hide() { close(false); }

    return {init, render, open, close, onSnapshot, hide, setLoading, setError};
})();

if (typeof module !== 'undefined' && module.exports) module.exports = ProcessWorkspace;
