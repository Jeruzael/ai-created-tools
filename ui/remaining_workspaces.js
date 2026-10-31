/* Milestone D presentation sidecar. No API, storage, diagnostic or scoring operations.
 * Embed each HTML asset as its entire tab section and load this CSS after shell styles.
 * Replace the help asset's process-guide placeholder before embedding, not at runtime.
 *
 * init({doc,win,page:Workspace.page,renderInstallerFiles}) binds ONLY new controls.
 * Core retains legacy filters, scan/export actions, history refresh and data-scan opening.
 * In core renderInstallerFiles: classify/filter exactly as before, then map the rows from
 * pageInstallerFiles(visible). Original file objects/evidence and manifest decisions survive.
 * Call renderInstallerSummary(data) after setting installer state/status/coverage and use
 * renderInstallerMissing(data?.missing_registered_files,{coverage:data?.coverage?.status})
 * instead of the old unbounded missing-file map. undefined/null means no recorded list.
 * refreshHistory passes response.records to renderHistory; Studio.updateHistory stays core-owned.
 * loadInitial passes info.version to renderAbout. Context help: navigate to manual, then
 * openProcessHelp(), which clears obscuring help filters and focuses the existing summary.
 *
 * Static pager IDs: <installerFiles|installerMissing|history><Search|Sort|PageSize|PageInfo|
 * Previous|Next|TableScroll>. Other IDs: installer-tab-/installer-view-<overview|packages|
 * coverage|missing|guidance>, installerSummaryDetails, installerAdditionalSummary,
 * installerCoverageNotice, installerMissingStatus, historyStatus, helpSearch, helpCategory,
 * helpTopics, helpResultsStatus, helpNoResults, help-category-<getting-started|disk-scanning|
 * results|process|security|installer|safety>, aboutAppVersion, aboutDocumentationVersion,
 * aboutTechnicalDetails. Every legacy ID stays in its replacement asset.
 */
const RemainingWorkspace = (() => {
    'use strict';
    const escape = value => String(value ?? '').replace(/[&<>"']/g,
        char => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'})[char]);
    const array = value => Array.isArray(value) ? value : [];
    const present = value => value !== undefined && value !== null && value !== '';
    const recorded = value => present(value) ? String(value) : 'Not recorded';
    const joined = value => array(value).filter(present).join('; ') || 'Unavailable';
    const numeric = value => present(value) && Number.isFinite(Number(value)) && Number(value) >= 0 ? Number(value) : null;
    const installerViews = ['overview', 'packages', 'coverage', 'missing', 'guidance'];
    const historyKeys = {date: '_remainingTime', size: '_remainingBytes', files: '_remainingFiles', skipped: '_remainingSkipped', root: 'root', status: 'status'};
    let bridge, doc, pages, historyRecords = null, missingFiles = null, missingCoverage = 'Unavailable';
    let historyLoading = false, historyError = '', helpOpenState = null;
    const bindings = [];
    const $ = id => doc.getElementById(id);

    function bind(element, type, handler) {
        element.addEventListener(type, handler); bindings.push([element, type, handler]);
    }

    function init(options) {
        bindings.splice(0).forEach(([element, type, handler]) => element.removeEventListener(type, handler));
        bridge = options; doc = options.doc;
        pages = Object.fromEntries(['installerFiles', 'installerMissing', 'history'].map(key =>
            [key, {page: 1, pageSize: 25, fingerprint: null}]));
        historyRecords = null; missingFiles = null; historyLoading = false; historyError = ''; helpOpenState = null;
        installerViews.forEach((name, index) => {
            const button = $('installer-tab-' + name);
            bind(button, 'click', () => selectInstaller(name));
            bind(button, 'keydown', event => {
                let next;
                if (event.key === 'Home') next = 0;
                else if (event.key === 'End') next = installerViews.length - 1;
                else if (event.key === 'ArrowRight') next = (index + 1) % installerViews.length;
                else if (event.key === 'ArrowLeft') next = (index + installerViews.length - 1) % installerViews.length;
                else return;
                event.preventDefault(); selectInstaller(installerViews[next]); $('installer-tab-' + installerViews[next]).focus();
            });
        });
        bindPager('installerFiles', () => bridge.renderInstallerFiles());
        bindPager('installerMissing', drawMissing);
        bindPager('history', drawHistory);
        bind($('helpSearch'), 'input', filterHelp);
        bind($('helpCategory'), 'change', filterHelp);
        selectInstaller('overview'); filterHelp();
        return RemainingWorkspace;
    }

    function selectInstaller(name) {
        if (!installerViews.includes(name)) name = 'overview';
        installerViews.forEach(view => {
            const active = name === view, tab = $('installer-tab-' + view);
            tab.setAttribute('aria-selected', String(active)); tab.tabIndex = active ? 0 : -1;
            $('installer-view-' + view).hidden = !active;
        });
    }

    function bindPager(key, render) {
        const settings = pages[key];
        $(key + 'PageSize').value = '25';
        const restart = () => { settings.page = 1; $(key + 'TableScroll').scrollTop = 0; render(); };
        bind($(key + 'Search'), 'input', restart);
        bind($(key + 'Sort'), 'change', restart);
        bind($(key + 'PageSize'), 'change', () => {
            const size = Number($(key + 'PageSize').value);
            if (![25, 50, 100].includes(size)) { $(key + 'PageSize').value = String(settings.pageSize); return; }
            settings.pageSize = size; restart();
        });
        for (const [suffix, delta] of [['Previous', -1], ['Next', 1]]) {
            bind($(key + suffix), 'click', () => {
                if ($(key + suffix).disabled) return;
                settings.page += delta; $(key + 'TableScroll').scrollTop = 0; render();
            });
        }
    }

    function pageRows(key, source, extraFilters = [], sortOverride) {
        const settings = pages[key], query = $(key + 'Search').value.trim().toLowerCase();
        const sort = $(key + 'Sort').value;
        const fingerprint = JSON.stringify([query, sort, ...extraFilters]);
        if (settings.fingerprint !== null && settings.fingerprint !== fingerprint) settings.page = 1;
        settings.fingerprint = fingerprint;
        const result = bridge.page(source, {query, sort: sortOverride || sort, page: settings.page, pageSize: settings.pageSize});
        settings.page = result.page;
        const first = result.total ? (result.page - 1) * result.pageSize + 1 : 0;
        $(key + 'PageInfo').textContent = `${first}-${Math.min(result.page * result.pageSize, result.total)} of ${result.total}; page ${result.page}/${result.pages}`;
        $(key + 'Previous').disabled = result.page === 1;
        $(key + 'Next').disabled = result.page === result.pages;
        $(key + 'PageSize').value = String(result.pageSize);
        return result;
    }

    function pageInstallerFiles(files) {
        const filters = ['installerStatusFilter', 'installerConfidenceFilter', 'installerTypeFilter', 'installerEligibilityFilter']
            .map(id => $(id).value).concat($('installerIncompleteOnly').checked);
        const result = pageRows('installerFiles', array(files), filters);
        $('installerVisibleCount').textContent = `${result.total} matching files (${array(files).length} after classification filters)`;
        return result.rows;
    }

    const metric = (label, value) => `<div class="metric"><div class="label">${escape(label)}</div><div class="value">${escape(recorded(value))}</div></div>`;

    function renderInstallerSummary(data) {
        const summary = data?.summary || {}, coverage = data ? data.coverage?.status || 'Unavailable' : 'Not run';
        $('installerCacheSummary').innerHTML = [
            ['Status', data ? summary.status : 'Not run'], ['MSI/MSP Files', summary.cache_files],
            ['Backup Review Candidates', summary.backup_review_candidates], ['Missing Registered', summary.missing_registered_files],
            ['Coverage', coverage],
        ].map(([label, value]) => metric(label, value)).join('');
        $('installerAdditionalSummary').innerHTML = [
            ['Direct References', summary.registered_files], ['Installed MSI Matches', summary.installed_product_matches],
            ['Registered MSP Matches', summary.registered_patch_matches], ['Installed MSP Targets', summary.installed_target_matches],
            ['Probable Orphans', summary.probable_orphans], ['Unknown', summary.unknown_files], ['Review Size', summary.orphan_candidate_size],
        ].map(([label, value]) => metric(label, value)).join('');
        const errors = Array.isArray(data?.errors) ? data.errors.length : null;
        $('installerCoverageNotice').textContent = data ?
            `Coverage: ${coverage}. ${errors === null ? 'Source note count not recorded.' : errors + ' source notes recorded.'} Incomplete or unavailable source evidence is not a clean result.` :
            'No installer cache scan has been run. Missing evidence is not a clean result.';
    }

    function renderInstallerMissing(files, options = {}) {
        missingFiles = Array.isArray(files) ? files : null;
        missingCoverage = options.coverage || 'Unavailable';
        drawMissing();
    }

    function drawMissing() {
        const scroll = $('installerMissingTableScroll'), top = scroll.scrollTop, left = scroll.scrollLeft;
        const result = pageRows('installerMissing', array(missingFiles));
        const empty = missingFiles === null ? 'No installer cache scan has been run.' : array(missingFiles).length && !result.total ?
            'No missing registered files match the current search.' : 'No missing registered cache files were reported.';
        $('installerMissingRows').innerHTML = result.rows.map(item => `<tr data-installer-missing><td><code>${escape(item.path || 'Unavailable')}</code></td><td>${escape(joined(item.products))}<br><span class="muted">${escape(joined(item.publishers))}</span></td><td>${escape(item.recommendation || 'Restore from original media or vendor repair if an installer asks for this cache file.')}</td></tr>`).join('') ||
            `<tr><td colspan="3">${escape(empty)}</td></tr>`;
        $('installerMissingStatus').textContent = `Source coverage: ${missingCoverage}. ${missingFiles === null ? 'Missing-file evidence not recorded.' : 'Missing evidence is not proof that all references were inspected.'}`;
        scroll.scrollTop = top; scroll.scrollLeft = left;
    }

    function sizeFromSummary(value) {
        const match = /^([0-9]+(?:\.[0-9]+)?)\s+(B|KB|MB|GB|TB|PB)$/.exec(String(value ?? '').trim());
        if (!match) return null;
        return Number(match[1]) * 1024 ** ['B', 'KB', 'MB', 'GB', 'TB', 'PB'].indexOf(match[2]);
    }

    function renderHistory(records) {
        historyRecords = Array.isArray(records) ? records : null;
        historyLoading = false; historyError = ''; drawHistory();
    }

    function drawHistory() {
        const scroll = $('historyTableScroll'), top = scroll.scrollTop, left = scroll.scrollLeft;
        const active = doc.activeElement, restoreId = active?.dataset?.scan;
        const restore = present(restoreId) && $('historyRows').contains(active);
        const source = array(historyRecords).map(row => {
            const timestamp = present(row.started_at) ? Date.parse(row.started_at) : NaN;
            return {...row, _remainingTime: Number.isFinite(timestamp) ? timestamp : null,
                _remainingBytes: sizeFromSummary(row.total_size), _remainingFiles: numeric(row.files_scanned),
                _remainingSkipped: numeric(row.skipped_count)};
        });
        const [key, direction] = $('historySort').value.split('-');
        const sort = historyKeys[key] && ['asc', 'desc'].includes(direction) ? historyKeys[key] + '-' + direction : '_remainingTime-desc';
        const result = pageRows('history', source, [], sort);
        const empty = historyRecords === null ? 'Scan history is not loaded.' : array(historyRecords).length ?
            'No scans match the current search.' : 'No scan history yet.';
        $('historyRows').innerHTML = result.rows.map(row => `<tr data-history-record="${escape(row.scan_id)}"><td>${escape(recorded(row.started_at))}</td><td>${escape(recorded(row.status))}</td><td><code>${escape(recorded(row.root))}</code></td><td>${escape(recorded(row.total_size))}</td><td>${escape(recorded(row.files_scanned))}</td><td>${escape(recorded(row.skipped_count))}</td><td>${present(row.scan_id) ? `<button type="button" data-scan="${escape(row.scan_id)}" aria-label="Open scan ${escape(row.scan_id)}">Open</button>` : 'Unavailable'}</td></tr>`).join('') || `<tr><td colspan="7">${escape(empty)}</td></tr>`;
        $('historyStatus').textContent = historyError ? `History refresh unavailable: ${historyError}${historyRecords !== null ? ' Showing the last recorded list.' : ''}` :
            historyLoading ? 'Loading saved scan history...' : historyRecords === null ? 'Scan history is not loaded.' :
            `${result.total} matching saved scans. Historical status and skipped counts are preserved.`;
        scroll.setAttribute('aria-busy', String(historyLoading));
        if (restore && !active.isConnected) {
            const replacement = Array.from($('historyRows').querySelectorAll('[data-scan]')).find(button => button.dataset.scan === restoreId);
            (replacement || $('historySearch')).focus({preventScroll: true});
        }
        scroll.scrollTop = top; scroll.scrollLeft = left;
    }

    function setHistoryLoading(value = true) { historyLoading = Boolean(value); if (historyLoading) historyError = ''; drawHistory(); }
    function setHistoryError(error) { historyLoading = false; historyError = error ? String(error.message || error) : ''; drawHistory(); }

    function filterHelp() {
        const query = $('helpSearch').value.trim().toLowerCase(), category = $('helpCategory').value;
        const topics = Array.from($('helpTopics').querySelectorAll('.help-topic'));
        const filtering = Boolean(query) || category !== 'all';
        if (filtering && helpOpenState === null) helpOpenState = new Map(topics.map(topic => [topic, topic.open]));
        let count = 0;
        $('helpTopics').querySelectorAll('[data-help-category]').forEach(section => {
            let sectionCount = 0;
            section.querySelectorAll('.help-topic').forEach(topic => {
                const matches = (category === 'all' || section.dataset.helpCategory === category) &&
                    (!query || (section.querySelector('h3').textContent + ' ' + topic.textContent).toLowerCase().includes(query));
                topic.hidden = !matches;
                if (matches) { count += 1; sectionCount += 1; if (query) topic.open = true; }
                if (!filtering && helpOpenState?.has(topic)) topic.open = helpOpenState.get(topic);
            });
            section.hidden = sectionCount === 0;
        });
        if (!filtering) helpOpenState = null;
        $('helpNoResults').hidden = count !== 0;
        $('helpResultsStatus').textContent = `${count} help topics${filtering ? ' match the current filters' : ' available locally'}.`;
    }

    function openProcessHelp() {
        $('helpSearch').value = ''; $('helpCategory').value = 'all'; filterHelp();
        const topic = $('processVerificationHelp');
        if (!topic || !$('helpTopics').contains(topic)) return false;
        topic.open = true; topic.querySelector('summary').focus(); return true;
    }

    function renderAbout(version) {
        $('aboutAppVersion').textContent = recorded(version?.app_version);
        $('aboutDocumentationVersion').textContent = recorded(version?.documentation_version);
        $('versionInfo').textContent = version && typeof version === 'object' ? JSON.stringify(version, null, 2) : 'Version metadata not recorded.';
    }

    return {init, selectInstaller, pageInstallerFiles, renderInstallerSummary, renderInstallerMissing,
        renderHistory, setHistoryLoading, setHistoryError, filterHelp, openProcessHelp, renderAbout};
})();

if (typeof module !== 'undefined' && module.exports) module.exports = RemainingWorkspace;
