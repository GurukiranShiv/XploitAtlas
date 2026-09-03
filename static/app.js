import {$,$$,icon,hydrateIcons,escapeHTML as esc,link,num,metric,percent,date,age,severityPill,priorityMarkup,empty,recordTable,eventMarkup,api,post,sourceNames} from './ui.js';
import {Universe} from './universe.js';

const PAGE_SIZE=40, NODE_LIMIT=4500;
const state={view:'universe',mode:'space',data:null,tablePage:0,tableRecords:[],matching:0,query:'',severity:'all',days:'0',kev:false,sort:'priority',detail:null,detailTab:'overview',detailToken:0,packageRecords:new Map(),eventsNext:null,learnRecord:null,learnStep:0,tourTimer:null};
let catalogController, debounceTimer, pollTimer, toastTimer, packageBusy=false, detailBusy=false;
hydrateIcons();
$('#today').textContent=new Intl.DateTimeFormat('en-GB',{day:'2-digit',month:'short',year:'numeric',timeZone:'UTC'}).format(new Date()).toUpperCase();
const universe=new Universe($('#universe'),$('#canvas-tooltip'),id=>openRecord(id),paused=>motionButton(paused));
motionButton(universe.paused);

function toast(message) {
  clearTimeout(toastTimer);$('#toast').textContent=message;$('#toast').hidden=false;
  toastTimer=setTimeout(()=>$('#toast').hidden=true,6000);
}
function notice(message) {$('#global-notice').textContent=message||'';$('#global-notice').hidden=!message;}
function motionButton(paused) {
  const button=$('#motion');button.innerHTML=icon(paused?'play':'pause');button.title=paused?'Resume orbit':'Pause orbit';
  button.setAttribute('aria-label',button.title);button.setAttribute('aria-pressed',String(paused));
}
function queryParams(limit=5000,offset=0) {
  return new URLSearchParams({q:state.query,severity:state.severity,days:state.days,kev:state.kev?'1':'0',sort:state.sort,limit:String(limit),offset:String(offset)});
}
function switchView(view) {
  if(!['universe','intelligence','changes','packages','sources','learn'].includes(view))return;
  state.view=view;
  if(view!=='universe')$('#canvas-tooltip').hidden=true;
  $$('.view').forEach(el=>el.hidden=el.id!=='view-'+view);
  $$('.nav-link').forEach(el=>{
    el.classList.toggle('active',el.dataset.view===view);
    if(el.dataset.view===view)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current');
  });
  universe.setVisible(view==='universe'&&state.mode==='space');
  if(view==='changes')loadChanges(false);
  if(view==='sources')renderSources();
  if(view==='intelligence')fetchTable();
  if(view==='learn')loadLearning();
  if(view!=='learn')stopTour();
  history.replaceState(null,'','#'+view);
}
function setMode(mode) {
  state.mode=mode;$('#universe-panel').hidden=mode!=='space';$('#inline-table-panel').hidden=mode!=='table';
  $$('[data-mode]').forEach(button=>{const active=button.dataset.mode===mode;button.classList.toggle('active',active);button.setAttribute('aria-pressed',String(active));});
  universe.setVisible(state.view==='universe'&&mode==='space');
  if(mode==='table')fetchTable();
}
function scheduleCatalog() {
  clearTimeout(debounceTimer);
  debounceTimer=setTimeout(()=>{state.tablePage=0;loadCatalog();},280);
}
function syncFilterInputs() {
  $('#search').value=state.query;$('#table-search').value=state.query;
  $('#severity').value=state.severity;$('#days').value=state.days;$('#kev-only').checked=state.kev;$('#sort').value=state.sort;
}
async function loadCatalog() {
  if(catalogController)catalogController.abort();
  tableRequest++;
  catalogController=new AbortController();
  const requested=new URLSearchParams(queryParams()).toString();
  try {
    const data=await api('/api/universe?'+requested,{signal:catalogController.signal});
    state.data=data;state.matching=data.matching;
    if(state.tablePage*PAGE_SIZE>=data.matching)state.tablePage=0;
    if(state.tablePage===0)state.tableRecords=data.records.slice(0,PAGE_SIZE);
    updateHealth(data);renderStatistics(data.stats);renderUniverse(data);renderRecent(data.recent);renderRadar(data.radar);
    renderTables();
    if(state.tablePage>0&&(state.view==='intelligence'||state.mode==='table'))fetchTable();
    if(state.view==='sources')renderSources();
    if(state.view==='learn'&&!state.learnRecord)loadLearning();
  } catch(error) {
    if(error.name==='AbortError')return;
    $('#connection-title').textContent='Catalog unavailable';$('#connection-detail').textContent='Check that the Python server is running';
    $('#connection-dot').className='status-dot error';
    notice(error.message+' Your last loaded observations remain on screen.');
    if(!state.data)$('#canvas-empty').innerHTML=empty('The catalog is not connected','Start the XploitAtlas Python server, then reload this page.');
  } finally {schedulePoll();}
}
function schedulePoll() {
  clearTimeout(pollTimer);
  pollTimer=setTimeout(async()=>{
    if(!document.hidden)await loadCatalog();else schedulePoll();
  },state.data?.sync?.running?7000:60000);
}
function updateHealth(data) {
  const sources=data.sources||[];
  const primary=sources.filter(s=>['cisa','nvd','github','epss'].includes(s.id));
  const errors=primary.filter(s=>s.state==='error');
  const successful=primary.filter(s=>s.lastSuccess);
  const stale=successful.filter(s=>Date.now()-new Date(s.lastSuccess).getTime()>86400000);
  const running=data.sync?.running;
  $('#connection-dot').className='status-dot'+(errors.length||stale.length?' pending':!successful.length?' pending':'');
  $('#connection-title').textContent=running?'Syncing authoritative sources':errors.length?'Some sources need attention':successful.length?'Real-source intelligence':'Waiting for first imports';
  $('#connection-detail').textContent=successful.length?successful.length+'/4 scheduled feeds have responded · '+age(data.lastSuccess):'No sample dataset · imports start automatically';
  $('#refresh').disabled=!!running;
  $('#refresh').innerHTML=icon('refresh')+'<span>'+(running?'Syncing…':'Sync feeds')+'</span>';
  $('#refresh').classList.toggle('loading-button',!!running);
  if(running)$('#refresh svg')?.classList.add('loading-icon');
  if(errors.length)notice(errors.map(s=>sourceNames[s.id]).join(', ')+' could not complete the latest request. Last successful observations are retained. Open Sources for retry times and coverage.');
  else if(stale.length)notice(stale.map(s=>sourceNames[s.id]).join(', ')+' have not completed a successful fetch in more than 24 hours. Review source timestamps before prioritizing.');
  else if(!data.sync?.schedulerActive)notice('Automatic imports are disabled in this server session. Start normally without --no-sync to keep the catalog updated.');
  else notice('');
  $('#footer-time').textContent=data.lastSuccess?'LAST CYCLE WITH DATA · '+date(data.lastSuccess,true).toUpperCase():'UTC · AWAITING SOURCE OBSERVATIONS';
}
function renderStatistics(stats) {
  $('#stat-total').textContent=num(stats.total);$('#stat-kev').textContent=num(stats.kev);
  $('#stat-critical').textContent=num(stats.critical);$('#stat-new').textContent=num(stats.newWeek);
}
function renderUniverse(data) {
  const records=data.records.slice(0,NODE_LIMIT);
  universe.setRecords(records);
  $('#node-count').textContent=num(records.length);
  $('#subset-note').textContent=data.matching>records.length?'of '+num(data.matching)+' matches':'';
  $('#inline-count').textContent=num(data.matching)+' matches';
  const emptyNode=$('#canvas-empty');emptyNode.hidden=records.length>0;
  if(!records.length) {
    const existing=data.stats.total>0;
    emptyNode.innerHTML='<span class="empty-orbit" aria-hidden="true"></span><h3>'+(existing?'No matching points':'Waiting for the first source')+'</h3><p>'+(existing?'Adjust the search or filters to explore your catalog.':'Real records appear as the upstream feeds respond.<br>No sample dataset is loaded.')+'</p><button class="button subtle" data-view="'+(existing?'intelligence':'sources')+'">'+(existing?'Open intelligence':'See source status')+' '+icon('arrow')+'</button>';
  }
  if(!universe.ctx) {
    emptyNode.hidden=false;
    emptyNode.innerHTML=empty('Use the accessible table','This browser could not create a canvas context. All records and evidence remain available.','<button class="button subtle" data-mode="table">Open table</button>');
  }
}
function renderRadar(records=[]) {
  $('#radar-list').innerHTML=records.length?records.map(r=>'<button class="radar-item" data-record="'+esc(r.id)+'"><span class="item-top"><span class="record-id">'+esc(r.id)+'</span><span class="pill coral-pill">'+(typeof r.cvss==='number'?metric(r.cvss):'—')+'</span></span><span class="item-title">'+esc(r.title)+'</span><span class="item-meta"><span>'+esc(r.vendor)+'</span><span>Added '+date(r.kevAdded)+'</span></span></button>').join(''):empty('Awaiting KEV','The official catalog has not supplied records yet.');
}
function renderRecent(records=[]) {
  $('#recent-grid').innerHTML=records.length?records.slice(0,4).map(r=>'<button class="recent-card" data-record="'+esc(r.id)+'"><span class="item-top"><span class="record-id">'+esc(r.id)+'</span>'+severityPill(r)+'</span><h3>'+esc(r.title)+'</h3><span class="card-footer"><span>'+esc(r.vendor)+'</span><span>'+date(r.published)+'</span></span></button>').join(''):empty('No publication dates yet','Recently published records will appear when NVD or package advisory imports respond.');
}
function renderTables() {
  const markup=recordTable(state.tableRecords);
  $('#intelligence-table').innerHTML=markup;$('#inline-table').innerHTML=markup;
  const count=state.matching,start=count?state.tablePage*PAGE_SIZE+1:0,end=Math.min(count,(state.tablePage+1)*PAGE_SIZE);
  $('#table-count').textContent=num(count)+' matching records';
  for(const prefix of ['table','inline']) {
    $('#'+prefix+'-page').textContent=num(start)+'–'+num(end)+' of '+num(count);
    $('#'+prefix+'-prev').disabled=state.tablePage===0;
    $('#'+prefix+'-next').disabled=end>=count;
  }
}
let tableRequest=0;
async function fetchTable() {
  const token=++tableRequest;
  const requested=queryParams(PAGE_SIZE,state.tablePage*PAGE_SIZE).toString();
  try {
    const data=await api('/api/universe?'+requested);
    if(token!==tableRequest||requested!==queryParams(PAGE_SIZE,state.tablePage*PAGE_SIZE).toString())return;
    state.tableRecords=data.records;state.matching=data.matching;renderTables();
  }catch(error){toast(error.message);}
}
async function turnPage(delta) {
  state.tablePage=Math.max(0,state.tablePage+delta);await fetchTable();
}
async function loadChanges(append=false) {
  try {
    const query=append&&state.eventsNext?'?before='+state.eventsNext:'';
    const data=await api('/api/events'+query);
    const html=data.events.map(eventMarkup).join('');
    if(append)$('#changes-list').insertAdjacentHTML('beforeend',html);
    else $('#changes-list').innerHTML=html||empty('A baseline, then real changes','Your first successful import establishes what is known. New observations and actual field changes will appear as subsequent source versions arrive.');
    state.eventsNext=data.nextBefore;$('#more-changes').hidden=!data.nextBefore;
    $('#history-baseline').textContent='Local observation history began '+date(data.baseline,true)+'. Publisher timestamps and local observation times are shown separately; no pre-installation history is invented.';
  }catch(error){if(!append)$('#changes-list').innerHTML=empty('History could not be loaded',error.message);else toast(error.message);}
}
function renderSources() {
  const data=state.data;if(!data)return;
  const sync=data.sync||{};
  $('#scheduler-status').innerHTML=icon('clock')+'<p><strong>'+(sync.running?'A real-source import is running.':sync.schedulerActive?'The background scheduler is active.':'The scheduler is disabled.')+'</strong> '+(sync.nextAt?'Next cycle no earlier than '+date(sync.nextAt,true)+'. ':'')+'Feeds update while this Python process is running, even when the browser is closed. Each upstream source can impose its own retry delay.</p>';
  $('#sources-grid').innerHTML=(data.sources||[]).map(s=>{
    const onDemand=['cve','osv'].includes(s.id);
    const status=s.state==='ok'?'Observed':s.state==='error'?'Retry pending':onDemand?'On demand':'Pending';
    return '<article class="panel source-card"><div class="source-header"><div><h3>'+esc(s.name)+'</h3>'+link(s.url,'Open source '+String.fromCharCode(8599))+'</div><span class="pill '+(s.state==='ok'?'lime-pill':s.state==='error'?'amber-pill':'')+'">'+status+'</span></div><p>'+esc(s.coverage)+'</p><dl><dt>Last successful fetch</dt><dd>'+date(s.lastSuccess,true)+'</dd><dt>Latest attempt</dt><dd>'+date(s.lastAttempt,true)+'</dd><dt>Last committed batch</dt><dd>'+num(s.count)+' observations</dd>'+(s.retryAt?'<dt>Retry no earlier than</dt><dd>'+date(s.retryAt,true)+'</dd>':'')+'</dl><p class="source-state">'+esc(s.message)+'</p></article>';
  }).join('');
}
function packageEvidence(packages) {
  if(!packages?.length)return empty('No package ranges supplied','This source record does not contain structured package information. Inspect the vendor advisory and remediation references.');
  return packages.map(p=>'<article class="package-evidence"><h4>'+esc(p.name||'Unnamed vendor product')+' <span class="pill">'+esc(p.ecosystem||'Unspecified')+'</span></h4><dl><dt>Affected</dt><dd>'+esc(p.affected||'Not supplied')+'</dd><dt>Fixed release(s)</dt><dd>'+esc(p.fixed||'No explicit fixed release supplied')+'</dd><dt>Evidence</dt><dd>'+link(p.url,sourceNames[p.source]||p.source)+'</dd></dl></article>').join('');
}
async function checkPackage(event) {
  event.preventDefault();if(packageBusy)return;
  packageBusy=true;const button=$('#package-submit');button.disabled=true;button.innerHTML=icon('refresh')+'Checking OSV…';
  $('#package-results').innerHTML=empty('Querying the authoritative feed','OSV is checking the exact ecosystem, package name, and version you supplied.');
  try {
    const data=await post('/api/package',{ecosystem:$('#package-ecosystem').value,name:$('#package-name').value.trim(),version:$('#package-version').value.trim()});
    state.packageRecords=new Map(data.records.map(r=>[r.id,r]));
    $('#package-result-count').textContent=num(data.records.length)+(data.partial?' · partial':' advisories');
    $('#package-results').innerHTML='<div class="package-query-note">'+esc(data.message)+' Checked '+date(data.checkedAt,true)+'.'+(data.partial?' The upstream result exceeds this request’s three-page limit; inspect OSV for the full result.':'')+'</div>'+
      (data.records.length?data.records.map(r=>'<article class="package-result"><div class="item-top"><button class="text-button record-id" data-record="'+esc(r.id)+'">'+esc(r.id)+' '+icon('arrow')+'</button>'+(r.kev?'<span class="pill coral-pill">CISA KEV</span>':'')+'</div><h3>'+esc(r.title)+'</h3>'+packageEvidence(r.packages)+'<button class="button subtle" data-record="'+esc(r.id)+'">Investigate evidence '+icon('arrow')+'</button></article>').join(''):empty('No matching published advisories','This is OSV’s response for this exact query. It is not a security certification or a guarantee that no vulnerability exists.'));
    loadCatalog();
  }catch(error){
    $('#package-result-count').textContent='Request failed';
    $('#package-results').innerHTML=empty('The package check did not complete',error.message);
  }finally{packageBusy=false;button.disabled=false;button.innerHTML=icon('search')+'Check published advisories';}
}
function showLoadingRecord(identifier) {
  $('#record-body').innerHTML='<div class="detail-loading"><div class="loading-line"></div><h2 id="record-heading">'+esc(identifier)+'</h2><p>Reading saved observations and requesting publisher evidence.</p><button class="button subtle" data-close>Close</button></div>';
}
async function openRecord(identifier) {
  const token=++state.detailToken;state.detailTab='overview';state.detail=null;detailBusy=false;
  showLoadingRecord(identifier);
  const dialog=$('#record-dialog');if(!dialog.open)dialog.showModal();
  let record=state.packageRecords.get(identifier);
  if(record){state.detail=record;renderDetail();}
  try {
    const saved=await api('/api/record?id='+encodeURIComponent(identifier));
    record=saved.record;
  }catch{/* A valid untracked CVE/GHSA can still be obtained from its publisher. */}
  if(token!==state.detailToken)return;
  if(record){state.detail=record;state.learnRecord=record;renderDetail();}
  await enrichRecord(identifier,token);
}
async function enrichRecord(identifier=state.detail?.id,token=state.detailToken) {
  if(!identifier)return;
  detailBusy=true;
  const current=state.detail;
  const alias=(current?.aliases||[]).find(a=>/^GHSA-[a-z0-9-]+$/.test(a));
  const button=$('[data-enrich]');if(button){button.disabled=true;button.innerHTML=icon('refresh')+'Fetching publisher…';}
  try {
    const data=await post('/api/enrich',{id:identifier,...(alias?{osv:alias}:{})});
    if(token!==state.detailToken)return;
    if(data.record){state.detail=data.record;state.learnRecord=data.record;renderDetail();}
    if(data.sources&&state.data)state.data.sources=data.sources;
  }catch(error){
    if(token!==state.detailToken)return;
    if(!state.detail)$('#record-body').innerHTML='<div class="detail-loading"><h2 id="record-heading">'+esc(identifier)+'</h2><p>'+esc(error.message)+'</p><button class="button subtle" data-close>Close</button></div>';
    else toast('Saved evidence remains available. '+error.message);
  }finally{
    if(token===state.detailToken){
      detailBusy=false;
      const button=$('[data-enrich]');if(button){button.disabled=false;button.innerHTML=icon('refresh')+'Refresh publisher evidence';}
    }
  }
}
function renderDetail() {
  const r=state.detail;if(!r)return;
  const checked=r.sources?.map(s=>s.observedAt).filter(Boolean).sort().at(-1);
  $('#record-body').innerHTML='<header class="detail-head"><button class="icon-button" data-close aria-label="Close investigation">'+icon('close')+'</button><div class="detail-top"><span class="record-id">'+esc(r.id)+'</span>'+severityPill(r)+(r.kev?'<span class="pill coral-pill">KNOWN EXPLOITED</span>':'')+(r.withdrawn?'<span class="pill amber-pill">WITHDRAWN / REJECTED</span>':'')+'</div><h2 id="record-heading">'+esc(r.title)+'</h2><p>'+esc(r.vendor)+' / '+esc(r.product)+' · Published '+date(r.published)+' · Updated by sources '+date(r.modified)+'</p></header>'+
    '<div class="detail-tabs" role="tablist" aria-label="Investigation views">'+[['overview','Overview'],['evidence','Evidence & sources'],['packages','Packages & fixes'],['history','Change history']].map(([id,label])=>'<button role="tab" id="detail-tab-'+id+'" aria-controls="detail-content" data-detail-tab="'+id+'" aria-selected="'+(state.detailTab===id)+'" class="'+(state.detailTab===id?'active':'')+'">'+label+'</button>').join('')+'</div><div class="detail-content" id="detail-content" role="tabpanel" aria-labelledby="detail-tab-'+state.detailTab+'"></div>'+
    '<footer class="detail-footer"><span>Most recent source observation: '+date(checked,true)+'</span><button class="text-button" data-copy="'+esc(r.id)+'">'+icon('copy')+'Copy ID</button></footer>';
  renderDetailTab();
}
function renderDetailTab() {
  const r=state.detail;if(!r)return;
  $$('[data-detail-tab]').forEach(b=>{const active=b.dataset.detailTab===state.detailTab;b.classList.toggle('active',active);b.setAttribute('aria-selected',String(active));});
  $('#detail-content').setAttribute('aria-labelledby','detail-tab-'+state.detailTab);
  if(state.detailTab==='overview') {
    const reasons=r.priority?.reasons||[];
    const conflicts=(r.conflicts||[]).map(c=>'<div class="notice">'+esc(c)+'</div>').join('');
    $('#detail-content').innerHTML=conflicts+'<div class="detail-metrics"><div class="detail-metric"><small>CVSS · technical severity</small><strong>'+metric(r.cvss)+'</strong><span>'+esc(sourceNames[r.cvssSource]||'No source metric')+'</span></div><div class="detail-metric"><small>EPSS · next 30 days</small><strong>'+percent(r.epss)+'</strong><span>'+date(r.epssDate)+'</span></div><div class="detail-metric"><small>Triage priority · heuristic</small><strong class="accent">'+num(r.priority.score)+'<span> / 100</span></strong><span>'+esc(r.priority.band)+'</span></div></div>'+
      '<div class="detail-description"><h3>What is known</h3><p>'+esc(r.description)+'</p>'+(r.vector?'<code class="vector">'+esc(r.vector)+'</code>':'')+(r.cwes?.length?'<div class="link-cluster">'+r.cwes.map(c=>'<span class="pill">'+esc(c)+'</span>').join('')+'</div>':'')+'</div>'+
      '<h3>Why this priority?</h3><ul class="priority-breakdown">'+(reasons.length?reasons.map(reason=>'<li><span>'+esc(reason.label)+'</span><b>+'+num(reason.points)+'</b></li>').join(''):'<li><span>No scored evidence has been supplied.</span><b>0</b></li>')+'</ul>'+
      '<p class="footnote">Model '+esc(r.priority.model)+': additive points, capped at 100. It is not a calibrated risk probability and does not know your asset exposure.'+(r.priority.missing?.length?' Missing inputs: '+esc(r.priority.missing.join(', '))+'. A low score with missing evidence does not establish low risk.':'')+'</p>'+
      '<section class="remediation"><h3>Next action</h3><p>'+esc(r.requiredAction||(r.packages?.some(p=>p.fixed)?'Compare your installed version and supported branch with the published affected ranges and fixed releases in Packages & fixes.':'Verify whether you run the affected product. Review the linked vendor advisory for fixes and mitigations. No precise remediation was supplied to this catalog.'))+'</p>'+
      (r.dueDate?'<p>CISA action due date: <strong>'+date(r.dueDate)+'</strong>. This catalog deadline applies to covered US federal agencies; use your own organization’s obligations and urgency.</p>':'')+'<p class="footnote">'+(r.kev?'CISA reports known exploitation. This does not establish that your environment is affected.':'No current KEV observation is present for this record. Absence from KEV is not proof that exploitation has never occurred.')+'</p></section>'+
      '<div class="overview-actions"><button class="button subtle" data-enrich '+(detailBusy?'disabled':'')+'>'+icon('refresh')+(detailBusy?'Fetching publisher…':'Refresh publisher evidence')+'</button><button class="button subtle" data-learn-record>'+icon('spark')+'Learn with this record</button></div>';
  } else if(state.detailTab==='evidence') {
    $('#detail-content').innerHTML='<h3>Source observations</h3><p class="footnote">Each source keeps its own timestamp and score. Canonical CVSS prefers CVE/CNA, then NVD, then GitHub. Source disagreement is preserved.</p>'+
      r.sources.map(s=>'<article class="source-evidence"><h4>'+esc(sourceNames[s.id]||s.id)+(typeof s.cvss==='number'?'<span class="pill">CVSS '+metric(s.cvss)+'</span>':'')+(s.withdrawn?'<span class="pill amber-pill">Withdrawn</span>':'')+'</h4><p>Observed '+date(s.observedAt,true)+' · Source updated '+date(s.modified,true)+' · '+esc(s.key)+'</p>'+link(s.url,'Open source record ↗')+'</article>').join('')+
      '<section class="detail-section"><h3>Vendor advisories, patches & exploit evidence</h3><p class="footnote">An “exploit” label comes from a publisher’s reference tag. XploitAtlas does not execute references or independently validate exploit reliability.</p>'+
      (r.references?.length?r.references.map(ref=>'<div class="reference-row"><span class="pill '+(ref.kind==='exploit'?'coral-pill':ref.kind==='patch'?'lime-pill':'')+'">'+esc(ref.kind)+'</span><div>'+link(ref.url,ref.url)+'<small>Attributed to '+esc(sourceNames[ref.source]||ref.source)+'</small></div></div>').join(''):empty('No references supplied','The saved source observations do not contain reference links.'))+'</section>';
  } else if(state.detailTab==='packages') {
    $('#detail-content').innerHTML='<h3>Affected software & published fixes</h3><p class="footnote">Ranges are preserved from publishers. OSV range events can describe several release branches; there may be more than one fixed version. A missing fixed release is unknown, not a claim that no patch exists.</p>'+packageEvidence(r.packages);
  } else {
    $('#detail-content').innerHTML=empty('Loading observed changes','Reading the locally saved source history.');
    const id=r.id,token=state.detailToken;
    api('/api/events?id='+encodeURIComponent(id)).then(data=>{
      if(token!==state.detailToken||state.detailTab!=='history')return;
      $('#detail-content').innerHTML='<p class="footnote">History begins with your saved observations. Initial source imports establish a baseline; earlier publisher history is not reconstructed.</p>'+(data.events.length?data.events.map(eventMarkup).join(''):empty('No changes observed yet','This record has no saved source differences since the baseline. Check back after later successful imports.'))+(data.nextBefore?'<p class="footnote">Showing the most recent 160 observations. Older observations remain in the local SQLite database.</p>':'');
    }).catch(error=>{if(token===state.detailToken&&state.detailTab==='history')$('#detail-content').innerHTML=empty('History is unavailable',error.message);});
  }
}
async function loadLearning() {
  if(state.learnRecord){renderLearning();return;}
  const selected=state.data?.radar?.[0]||state.data?.records?.[0];
  if(!selected){$('#learn-record').textContent='Waiting for a real record';$('#learn-explanation').innerHTML=empty('Start with a real source','The walkthrough becomes available after an import supplies at least one real vulnerability.');return;}
  try {const data=await api('/api/record?id='+encodeURIComponent(selected.id));state.learnRecord=data.record;renderLearning();}
  catch(error){$('#learn-explanation').innerHTML=empty('The record could not be loaded',error.message);}
}
function renderLearning() {
  const r=state.learnRecord;if(!r)return;
  $('#learn-record').textContent=r.id+' · real source record';
  $$('.flow-step').forEach(b=>{const selected=Number(b.dataset.step)===state.learnStep;b.classList.toggle('active',selected);b.setAttribute('aria-pressed',String(selected));});
  const evidenceCount=r.references.filter(ref=>ref.kind==='exploit').length;
  const slides=[
    {eyebrow:'01 / IDENTITY',title:'Start with what was disclosed.',body:'A CVE is a shared identifier for a published vulnerability. It connects records from different sources, but the identifier alone says nothing about severity, exploitation, or whether your software is affected.',evidence:'<strong>'+esc(r.id)+'</strong><p>'+esc(r.title)+'</p><p>Publisher date: '+date(r.published)+'. Product: '+esc(r.product)+'.</p>',action:'Match the product and version against your actual software inventory. Check aliases and the original publisher record.'},
    {eyebrow:'02 / IMPACT',title:'Separate severity from probability.',body:'CVSS describes technical severity under specified conditions. EPSS estimates exploitation probability over the next 30 days. A severe vulnerability can have a different priority once exposure and exploitation evidence are considered.',evidence:'<strong>CVSS '+metric(r.cvss)+' · EPSS '+percent(r.epss)+'</strong><p>CVSS source: '+esc(sourceNames[r.cvssSource]||'No metric supplied')+'. EPSS date: '+date(r.epssDate)+'.</p>'+(r.vector?'<code class="vector">'+esc(r.vector)+'</code>':'<p>No CVSS vector was supplied. Unknown values remain unknown.</p>'),action:'Read the vector and its conditions. Do not interpret a missing score as zero or an EPSS prediction as proof of exploitation.'},
    {eyebrow:'03 / EVIDENCE',title:'Ask what has actually been observed.',body:'CISA KEV records confirmed exploitation in the wild. Publisher-tagged exploit references provide a different type of evidence: a link to inspect. They do not by themselves prove current attacks or successful exploitation in your environment.',evidence:'<strong>'+(r.kev?'This record is in CISA KEV.':'No current KEV observation for this record.')+'</strong><p>'+(r.kev?'Added to KEV: '+date(r.kevAdded)+'. ':'')+num(evidenceCount)+' source-tagged exploit references. Ransomware evidence: '+esc(r.ransomware)+'.</p>',action:'Follow the evidence back to its source and timestamp. Verify prerequisites, source reliability, and whether your systems meet the affected conditions.'},
    {eyebrow:'04 / RESPONSE',title:'Turn evidence into a defensible action.',body:'The triage model makes its inputs visible. It is a starting point for review; the final decision also needs asset exposure, business impact, compensating controls, and a supported remediation path.',evidence:'<strong>'+esc(r.priority.band)+' · '+num(r.priority.score)+'/100 heuristic</strong><ul>'+r.priority.reasons.map(reason=>'<li>'+esc(reason.label)+' (+'+num(reason.points)+')</li>').join('')+'</ul><p>'+esc(r.requiredAction||'Consult Packages & fixes and linked vendor advisories for exact remediation.')+'</p>',action:'Confirm the affected version, choose the appropriate patched branch or mitigation, test the change, and verify remediation on your assets.'}
  ];
  const slide=slides[state.learnStep];
  $('#learn-explanation').innerHTML='<span class="eyebrow accent">'+slide.eyebrow+'</span><h3>'+slide.title+'</h3><p>'+slide.body+'</p><div class="learn-evidence">'+slide.evidence+'</div><h4>What to do next</h4><p>'+slide.action+'</p><div class="learn-nav"><button class="button subtle" data-tour-next="-1" '+(state.learnStep===0?'disabled':'')+'>Previous</button><button class="button primary" data-tour-next="1">'+(state.learnStep===3?'Start again':'Next step')+' '+icon('arrow')+'</button></div>';
}
function stopTour(){clearInterval(state.tourTimer);state.tourTimer=null;$('#flow-track').classList.remove('playing');$('#tour-motion').innerHTML=icon('play')+'<span>Play walkthrough</span>';}
function toggleTour(){
  if(state.tourTimer){stopTour();return;}
  if(!state.learnRecord){toast('Wait for a real record to arrive from the sources.');return;}
  if(matchMedia('(prefers-reduced-motion: reduce)').matches){toast('Reduced motion is enabled. Use the numbered steps or Next step.');return;}
  $('#flow-track').classList.add('playing');$('#tour-motion').innerHTML=icon('pause')+'<span>Pause walkthrough</span>';
  state.tourTimer=setInterval(()=>{state.learnStep=(state.learnStep+1)%4;renderLearning();},9000);
}

document.addEventListener('click',event=>{
  const view=event.target.closest('[data-view]');if(view){switchView(view.dataset.view);return;}
  const record=event.target.closest('[data-record]');if(record){openRecord(record.dataset.record);return;}
  const mode=event.target.closest('[data-mode]');if(mode){setMode(mode.dataset.mode);return;}
  const tab=event.target.closest('[data-detail-tab]');if(tab){state.detailTab=tab.dataset.detailTab;renderDetailTab();return;}
  const step=event.target.closest('[data-step]');if(step){stopTour();state.learnStep=Number(step.dataset.step);renderLearning();return;}
  const next=event.target.closest('[data-tour-next]');if(next){stopTour();state.learnStep=(state.learnStep+Number(next.dataset.tourNext)+4)%4;renderLearning();return;}
  if(event.target.closest('[data-close]')){$('#record-dialog').close();return;}
  if(event.target.closest('[data-enrich]')){if(!detailBusy)enrichRecord();return;}
  if(event.target.closest('[data-learn-record]')){state.learnRecord=state.detail;$('#record-dialog').close();switchView('learn');return;}
  const copy=event.target.closest('[data-copy]');
  if(copy){if(navigator.clipboard)navigator.clipboard.writeText(copy.dataset.copy).then(()=>toast('Identifier copied.')).catch(()=>toast('Select and copy the identifier from the record header.'));else toast('Select and copy the identifier from the record header.');return;}
});
$('#filters').addEventListener('submit',event=>{
  event.preventDefault();clearTimeout(debounceTimer);state.query=$('#search').value.trim();syncFilterInputs();state.tablePage=0;loadCatalog();
  if(/^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$/.test(state.query))openRecord(state.query);
});
$('#search').addEventListener('input',event=>{state.query=event.target.value.trim();$('#table-search').value=state.query;scheduleCatalog();});
$('#table-search').addEventListener('input',event=>{state.query=event.target.value.trim();$('#search').value=state.query;scheduleCatalog();});
$('#severity').addEventListener('change',event=>{state.severity=event.target.value;scheduleCatalog();});
$('#days').addEventListener('change',event=>{state.days=event.target.value;scheduleCatalog();});
$('#kev-only').addEventListener('change',event=>{state.kev=event.target.checked;scheduleCatalog();});
$('#sort').addEventListener('change',event=>{state.sort=event.target.value;scheduleCatalog();});
$('#reset-filters').addEventListener('click',()=>{state.query='';state.severity='all';state.days='0';state.kev=false;state.sort='priority';state.tablePage=0;syncFilterInputs();loadCatalog();});
$('#see-kev').addEventListener('click',()=>{state.kev=true;state.query='';state.days='0';state.severity='all';state.tablePage=0;syncFilterInputs();loadCatalog();$('#filters').scrollIntoView({block:'center'});});
$('#see-recent').addEventListener('click',()=>{state.days='7';state.kev=false;state.query='';state.severity='all';state.sort='newest';state.tablePage=0;syncFilterInputs();switchView('intelligence');loadCatalog();});
$('#table-filters').addEventListener('click',()=>{switchView('universe');$('#filters').scrollIntoView({block:'center'});$('#search').focus();});
for(const prefix of ['table','inline']){$('#'+prefix+'-prev').addEventListener('click',()=>turnPage(-1));$('#'+prefix+'-next').addEventListener('click',()=>turnPage(1));}
$('#refresh').addEventListener('click',async()=>{
  $('#refresh').disabled=true;
  try{const result=await post('/api/sync');toast(result.message);setTimeout(()=>loadCatalog(),1200);}
  catch(error){toast(error.message);$('#refresh').disabled=false;}
});
$('#zoom-in').addEventListener('click',()=>universe.setZoom(universe.zoom*1.2));
$('#zoom-out').addEventListener('click',()=>universe.setZoom(universe.zoom/1.2));
$('#reset-camera').addEventListener('click',()=>universe.reset());
$('#motion').addEventListener('click',()=>motionButton(universe.toggle()));
$('#fullscreen').addEventListener('click',async()=>{
  try{if(document.fullscreenElement)await document.exitFullscreen();else if($('#universe-panel').requestFullscreen)await $('#universe-panel').requestFullscreen();else toast('Fullscreen is unavailable in this browser.');}
  catch{toast('The browser could not enter fullscreen.');}
});
$('#reload-changes').addEventListener('click',()=>loadChanges(false));
$('#more-changes').addEventListener('click',()=>loadChanges(true));
$('#package-form').addEventListener('submit',checkPackage);
$('#tour-motion').addEventListener('click',toggleTour);
$('#learn-inspect').addEventListener('click',()=>{if(state.learnRecord)openRecord(state.learnRecord.id);else toast('A real source record is needed first.');});
$('#record-dialog').addEventListener('click',event=>{if(event.target===$('#record-dialog'))$('#record-dialog').close();});
$('#record-dialog').addEventListener('close',()=>{state.detailToken++;detailBusy=false;});
document.addEventListener('keydown',event=>{
  if(event.key==='/'&&!['INPUT','TEXTAREA','SELECT'].includes(document.activeElement?.tagName)&&!$('#record-dialog').open){event.preventDefault();switchView('universe');$('#search').focus();}
  const tab=event.target.closest?.('[data-detail-tab]');
  if(tab&&['ArrowLeft','ArrowRight','Home','End'].includes(event.key)){
    event.preventDefault();const tabs=$$('[data-detail-tab]');const index=tabs.indexOf(tab);
    const next=event.key==='Home'?0:event.key==='End'?tabs.length-1:(index+(event.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;
    tabs[next].focus();state.detailTab=tabs[next].dataset.detailTab;renderDetailTab();
  }
});
document.addEventListener('visibilitychange',()=>{if(document.hidden)stopTour();else loadCatalog();});
window.addEventListener('hashchange',()=>switchView(location.hash.slice(1)||'universe'));
switchView(location.hash.slice(1)||'universe');
loadCatalog();
