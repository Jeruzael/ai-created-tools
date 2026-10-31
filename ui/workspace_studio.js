/* Local presentation adapter. Collectors, scoring, persistence and API stay in the core. */
const Workspace = (()=>{
    'use strict';
    const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const list=v=>Array.isArray(v)?v.filter(x=>x&&typeof x==='object'&&!Array.isArray(x)):[];
    const available=v=>v===undefined||v===null||v===''?'Unavailable':v;
    let ui;

    function page(items,options={}) {
        const query=String(options.query??'').trim().toLowerCase();
        const rows=list(items).filter(row=>!query||JSON.stringify(row).toLowerCase().includes(query));
        const match=/^(.*)-(asc|desc)$/.exec(options.sort||'');
        if(match){const [,key,direction]=match;rows.sort((a,b)=>{
            const av=a[key],bv=b[key];
            if(av===undefined||av===null||av==='')return bv===undefined||bv===null||bv===''?0:1;
            if(bv===undefined||bv===null||bv==='')return -1;
            const result=typeof av==='number'&&typeof bv==='number'?av-bv:String(av).localeCompare(String(bv));
            return direction==='desc'?-result:result;
        });}
        const pageSize=[25,50,100].includes(options.pageSize)?options.pageSize:25;
        const pages=Math.max(1,Math.ceil(rows.length/pageSize));
        const current=Math.max(1,Math.min(pages,Number.isInteger(options.page)?options.page:1));
        return {rows:rows.slice((current-1)*pageSize,current*pageSize),total:rows.length,page:current,pages,pageSize};
    }

    function stepRows(value,status) {
        const rows=list(value);const terminal=['completed','cancelled','failed','error'].includes(status?.status);
        if(!rows.length)return [{label:'Execution evidence',status:status?.check_id?'Not recorded':'Not run',detail:'No saved step outcomes are available.'}];
        return rows.map(step=>{
            const row={...step};const old=String(step.status||'').toLowerCase();
            if(terminal&&['waiting','pending','queued'].includes(old))row.status='Not run';
            else if(terminal&&old==='running')row.status=status.status==='cancelled'?'Cancelled':'Unfinished';
            else if(!old)row.status='Not recorded';
            if(row.status!==step.status)row.detail=`${step.detail||''} Saved step status: ${step.status||'not recorded'}; run ${status?.status||'not run'}.`.trim();
            return row;
        });
    }

    function outcome(value) { return String(value||'not_recorded').replaceAll('_',' ').replace(/^./,c=>c.toUpperCase()); }
    function coverageModel(status,coverage) { return {status:coverage?.recorded?coverage.status:(status?.check_id?'Not recorded':'Not run'),terminal:status?.status||'Not run',entries:coverage?.recorded?list(coverage.entries):[]}; }
    function field(label,value) { return `<div class="workspace-field"><strong>${esc(label)}</strong><pre>${esc(available(value))}</pre></div>`; }

    function tabs(prefix,names,active) {
        names.forEach(name=>{
            const selected=name===active;
            const button=ui.el(prefix+'-tab-'+name);button.setAttribute('aria-selected',String(selected));button.tabIndex=selected?0:-1;
            ui.el(prefix+'-view-'+name).classList.toggle('hidden',!selected);
        });
    }

    function bindTabs(prefix,names,callback) {
        names.forEach((name,index)=>{
            const button=ui.el(prefix+'-tab-'+name);
            button.addEventListener('click',()=>callback(name));
            button.addEventListener('keydown',event=>{
                if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;
                event.preventDefault();const next=event.key==='Home'?0:event.key==='End'?names.length-1:(index+(event.key==='ArrowRight'?1:-1)+names.length)%names.length;
                callback(names[next]);ui.el(prefix+'-tab-'+names[next]).focus();
            });
        });
    }

    function selectSecurity(name) {
        const names=['run','findings','coverage','baselines','allowlist','timeline','reports'];
        ui.securityView=names.includes(name)?name:'run';tabs('security',names,ui.securityView);
    }

    function paginate(id,source,settings,render,columns) {
        const result=page(source,settings);settings.page=result.page;
        ui.el(id).innerHTML=result.rows.map(render).join('')||`<tr><td colspan="${columns}">${settings.query?'No matching evidence.':'No evidence recorded for this view. Check run status and coverage.'}</td></tr>`;
        const target=ui.el(settings.pager);
        const first=result.total?(result.page-1)*result.pageSize+1:0;
        if(!target.querySelector('[data-workspace-size]'))target.innerHTML=`<span role="status"></span><label>Rows<select data-workspace-size="${settings.key}" aria-label="Rows per page">${[25,50,100].map(n=>`<option>${n}</option>`).join('')}</select></label><button class="icon-button" data-workspace-page="${settings.key}" data-delta="-1" aria-label="Previous page" title="Previous page"><svg class="icon" aria-hidden="true"><use href="#icon-chevron-left"></use></svg></button><button class="icon-button" data-workspace-page="${settings.key}" data-delta="1" aria-label="Next page" title="Next page"><svg class="icon" aria-hidden="true"><use href="#icon-chevron-right"></use></svg></button>`;
        target.querySelector('[role="status"]').textContent=`${first}-${Math.min(result.page*result.pageSize,result.total)} of ${result.total}; page ${result.page}/${result.pages}`;
        target.querySelector('select').value=String(result.pageSize);
        target.querySelector('[data-delta="-1"]').disabled=result.page===1;
        target.querySelector('[data-delta="1"]').disabled=result.page===result.pages;
        return result;
    }

    function renderFindings(status) {
        if(!ui)return;ui.securityStatus=status;
        if(ui.findingRecord!==status?.check_id){ui.pages.findings.page=1;ui.findingRecord=status?.check_id;closeFinding(false);ui.bridge.readState().selectedSecurityFindingId=null;}
        const filters=['securityFindingFilter','securitySeverityFilter','securityCategoryFilter','securityStatusFilter','securitySignalFilter','securityBaselineFilter','securityFindingsSort'];
        const fingerprint=filters.map(id=>ui.el(id).value).join('\u0000');
        if(ui.findingFilter!==fingerprint){ui.findingFilter=fingerprint;ui.pages.findings.page=1;}
        ui.pages.findings.sort=ui.el('securityFindingsSort').value;
        const rows=ui.bridge.filteredFindings(status);
        paginate('securityFindingsRows',rows,ui.pages.findings,f=>{
            const selected=ui.bridge.readState().selectedSecurityFindingId===f.finding_id;
            const reasons=Array.isArray(f.review_reasons)?f.review_reasons.join('; '):f.status||'Review evidence';
            return `<tr class="security-finding-row${selected?' selected':''}" tabindex="0" role="button" aria-label="Open finding ${esc(f.title)}" data-security-finding="${esc(f.finding_id)}"><td>${esc(available(f.severity))}</td><td>${esc(available(f.score))}</td><td>${esc(available(f.category))}</td><td>${esc(f.title||'Untitled')}<br>${esc(f.baseline_status||'')}${f.allowlist_status?'<span class="security-badge">Allowlist match; not proof of safety</span>':''}</td><td>${esc(reasons)}</td><td><button data-security-finding="${esc(f.finding_id)}">Details</button></td></tr>`;
        },6);
        const selected=ui.bridge.readState().selectedSecurityFindingId;
        if(ui.el('findingInspector').open&&selected){
            const finding=list(status?.findings).find(f=>f.finding_id===selected);
            if(!finding){closeFinding(false);return;}
            const key=JSON.stringify([status?.check_id,finding]);
            if(key!==ui.findingContentKey){ui.bridge.renderFindingContent(status,selected);ui.findingContentKey=key;}
        }
    }

    function openFinding(status,id) {
        const finding=list(status?.findings).find(row=>row.finding_id===id);if(!finding)return;
        const drawer=ui.el('findingInspector');
        if(!drawer.open)ui.findingOpener=ui.doc.activeElement;
        ui.bridge.readState().selectedSecurityFindingId=id;
        ui.bridge.renderFindingContent(status,id);ui.findingContentKey=JSON.stringify([status?.check_id,finding]);
        selectSecurity('findings');
        if(!drawer.open)drawer.showModal();
        ui.el('closeFindingInspector').focus();
    }

    function closeFinding(restore=true) {
        const drawer=ui.el('findingInspector');if(drawer.open)drawer.close();
        if(restore)(ui.findingOpener?.isConnected===false?ui.el('security-tab-findings'):ui.findingOpener||ui.el('security-tab-findings')).focus();
    }

    function renderCoverage(status) {
        if(!ui)return;const view=ui.bridge.coverage(status);const model=coverageModel(status,view);
        const warning=ui.el('securityCoverageWarning');warning.classList.toggle('complete',model.status==='complete');
        warning.textContent=`Collector coverage: ${model.status}. ${model.status==='complete'?'Complete within declared scopes only; not a safety verdict.':'Missing or incomplete evidence is not a clean result.'}`;
        ui.el('securityCoverageEvidence').innerHTML=`<h3>Collector and source outcomes</h3><p>Run: ${esc(model.terminal)}. Coverage: ${esc(outcome(model.status))}.</p>`+(model.entries.length?`<div class="table-wrap workspace-table"><table class="coverage-outcomes"><thead><tr><th>Collector</th><th>Outcome</th><th>Scope</th><th>Source evidence</th></tr></thead><tbody>${model.entries.map(entry=>`<tr><td>${esc(entry.category)}</td><td>${esc(outcome(entry.status))}</td><td>${esc(entry.scope)}</td><td><details><summary>${list(entry.sources).length} recorded source outcomes</summary>${list(entry.sources).map(source=>`<p><strong>${esc(source.source)}</strong>: ${esc(outcome(source.status))}</p><pre>${esc(source.reason_code||'')} ${esc(source.detail||'')}</pre>`).join('')||'<p>Source outcomes not recorded.</p>'}<p>${esc(entry.reason_code||'')}</p></details></td></tr>`).join('')}</tbody></table></div>`:'<p>No validated collector ledger. Historical missing evidence remains not recorded.</p>');
        ui.el('securityRunDetails').innerHTML=field('Run status',status?.status)+field('Skipped-source evidence',list(status?.skipped_items).map(row=>`${row.category}: ${row.status||'Unavailable'} - ${row.message||row.detail||''}`).join('\n'));
    }

    function renderTimeline(status) {
        if(!ui)return;const rows=ui.bridge.timeline(status);
        const settings=ui.pages.timeline;settings.query=ui.el('securityTimelineSearch').value;settings.sort=ui.el('securityTimelineSort').value;
        const normalized=rows.map(row=>({...row,sortTime:row.missingTime?null:row.sortTime}));
        ui.el('securityTimelineSummary').innerHTML=`<span>${rows.length} evidence events; ${rows.filter(row=>row.missingTime).length} missing times. Chronology is not causation.</span>`;
        paginate('securityTimelineRows',normalized,settings,row=>`<tr><td>${esc(row.time||'Time unavailable')}</td><td>${esc(row.type)}</td><td>${esc(row.item)}</td><td><details><summary>${esc(String(row.summary||'No details').slice(0,90))}</summary><p>${esc(row.summary)}</p></details></td><td>${esc(row.severity)}</td><td>${row.findingId?`<button data-timeline-finding="${esc(row.findingId)}">Linked finding</button>`:'No linked finding'}</td></tr>`,6);
    }

    function init(bridge) {
        ui={bridge,doc:bridge.doc,win:bridge.win,el:id=>bridge.doc.getElementById(id),securityStatus:null,
            pages:{findings:{key:'findings',pager:'securityFindingsPager',page:1,pageSize:25},timeline:{key:'timeline',pager:'securityTimelinePager',page:1,pageSize:25}}};
        bindTabs('security',['run','findings','coverage','baselines','allowlist','timeline','reports'],selectSecurity);selectSecurity('run');
        ui.el('closeFindingInspector').addEventListener('click',()=>closeFinding());
        ui.el('findingInspector').addEventListener('cancel',event=>{event.preventDefault();closeFinding();});
        ui.el('securityFindingsSort').addEventListener('change',()=>renderFindings(ui.bridge.readState().currentSecurityStatus));
        for(const id of ['securityTimelineSearch','securityTimelineSort'])ui.el(id).addEventListener(id.endsWith('Search')?'input':'change',()=>{ui.pages.timeline.page=1;renderTimeline(ui.bridge.readState().currentSecurityStatus);});
        ui.doc.addEventListener('click',event=>{const button=event.target.closest('[data-workspace-page]');if(button){const setting=ui.pages[button.dataset.workspacePage];if(setting){setting.page+=Number(button.dataset.delta)||0;rerender(setting.key);}}});
        ui.doc.addEventListener('change',event=>{const key=event.target.dataset.workspaceSize;if(ui.pages[key]){ui.pages[key].pageSize=Number(event.target.value);ui.pages[key].page=1;rerender(key);}});
    }

    function rerender(key) { const status=ui.bridge.readState().currentSecurityStatus;if(key==='findings')renderFindings(status);else if(key==='timeline')renderTimeline(status); }
    function onNavigate(name) { if(ui&&name!=='security')closeFinding(false); }
    return {page,stepRows,coverageModel,outcome,field,init,selectSecurity,renderFindings,openFinding,closeFinding,renderCoverage,renderTimeline,onNavigate};
})();
if(typeof module!=='undefined'&&module.exports)module.exports=Workspace;
