import {$,$$,escapeHTML as esc,icon,hydrateIcons,link,num,metric,percent,date,age,severityPill,priorityMarkup,empty,recordTable,eventMarkup,sourceNames} from './ui.js';
import {rendererPresentation} from './renderer-status.js';
import {discoveryMarkup,sourceStrip,recordSummary,overviewMarkup,evidenceMarkup,packageEvidence,recordGraphModel,learningMarkup,learningBrief} from './osint.js';
import {comparisonForm,comparisonMarkup,componentComparisonView,componentComparisonMarkup,highlightComposer,highlightPage,taxonomyMarkup,aiIntro,aiMarkup} from './briefing.js';

const S={user:null,public:false,setup:false,view:'discover',epoch:0,inventory:'',findingOffset:0,resolved:false,
  catalog:{q:'',severity:'all',kev:false,days:'0',sort:'priority',offset:0},inventories:[],findings:[],
  profile:{weights:{},filters:[]},events:[],trendDays:30,trendBasis:'source',inboxOffset:0,universe:null,universeRecords:[],
  requests:{},learnRecord:null,learnStep:0,learnFocus:0,learnChecks:[],record:null,recordTab:'overview',revision:null,
  installPrompt:null,ai:null,highlightDraft:{title:'',note:'',items:[]},sharedToken:new URLSearchParams(location.search).get('highlight')||'',
  comparison:{from:new Date(Date.now()-6*86400000).toISOString().slice(0,10),to:new Date().toISOString().slice(0,10),result:null},
  componentComparison:{left:{ecosystem:'npm',name:'',version:''},right:{ecosystem:'npm',name:'',version:''},result:null},
  universeKnown:new Set(),universeBaseline:null};
const publicViews=['discover','catalog','components','sources','changes','universe','learn'];
const viewInfo={
  discover:['OSINT DISCOVERY','Discover. Investigate. Understand.','New disclosures and exploitation evidence from public sources, with a path into each record.'],
  learn:['INVESTIGATION LAB','Learn by examining a real CVE.','Decode disclosure, severity, exploitation, and response evidence without leaving the selected record.'],
  workspace:['OPTIONAL PACKAGE TOOLS','Your saved package checks.','An optional workspace for checking software inventories.'],
  catalog:['PUBLIC INTELLIGENCE','Follow the evidence.','Search the collected catalog and open the source behind each finding.'],
  components:['EXACT-VERSION EVIDENCE','Compare two software components.','See where current OSV advisory matches overlap, differ, and remain incomplete—then publish an evidence badge.'],
  changes:['CHANGE INTELLIGENCE','See what changed—and open the evidence.','Compare provider dates with local observations, then investigate the records behind each count.'],
  highlights:['CURATED INTELLIGENCE','A few records. A clearer story.','Build a sourced briefing with collected vulnerabilities and your own clearly labelled notes.'],
  watchlists:['OPTIONAL WATCHLISTS','Follow the evidence that matters.','Save a CVE, vendor, product, or package watch and follow matching changes.'],
  sources:['COVERAGE & PROVENANCE','Know your sources.','Check freshness, import progress, and the publishers behind the evidence.'],
  universe:['EVIDENCE COSMOS','Explore the vulnerability landscape.','Enter fullscreen, navigate vendor systems, and select a CVE to open its source evidence.'],
  settings:['INSTANCE & OPTIONAL TOOLS','Manage your instance.','Administration, saved watches, and optional package tools.']
};
const labels={kev:'Known exploitation',ransomware:'Ransomware evidence',cvss:'Technical severity',epss:'EPSS probability',
  exploit_reference:'Published exploit references',internet_exposed:'Internet exposure',asset_criticality:'Asset importance'};
const button=(text,action,kind='')=>'<button type="button" data-action="'+action+'" class="'+kind+'">'+text+'</button>';
const opt=(value,label,current)=>'<option value="'+esc(value)+'"'+(String(value)===String(current)?' selected':'')+'>'+esc(label)+'</option>';
const pill=(text,tone='')=>'<span class="pill '+tone+'-pill">'+esc(text)+'</span>';
function toast(message,error=false){const el=$('#toast');el.textContent=message;el.className='toast'+(error?' error':'');el.hidden=false;clearTimeout(S.toastTimer);S.toastTimer=setTimeout(()=>el.hidden=true,error?9000:5000);}
function message(error){return error instanceof Error?error.message:String(error);}
async function api(path,body,signal){
  const response=await fetch(path,{credentials:'same-origin',cache:'no-store',headers:body!==undefined?{'Content-Type':'application/json','X-CSRF-Token':S.user?.csrf||''}:{},
    ...(body!==undefined?{method:'POST',body:JSON.stringify(body)}:{}),signal});
  const data=await response.json();
  if(!response.ok){
    if(response.status===401&&S.user){S.user=null;S.profile={weights:{},filters:[]};S.inventories=[];S.findings=[];S.highlightDraft={title:'',note:'',items:[]};$('#dialog').close();showAuth();}
    const error=new Error(data.error||data.message||'Request could not be completed.');error.status=response.status;throw error;
  }
  return data;
}
function openDialog(title,body){S.graph?.dispose();S.graph=null;S.universe?.setVisible(false);S.dialogEpoch=(S.dialogEpoch||0)+1;$('#dialog-title').textContent=title;$('#dialog-content').innerHTML=body;hydrateIcons($('#dialog'));if(!$('#dialog').open)$('#dialog').showModal();}
function showAuth(){S.graph?.dispose();S.graph=null;S.graphModel=null;S.evidence=null;$('#dialog').close();$('#view').replaceChildren();$('#universe-table').replaceChildren();$('#universe-selection').replaceChildren();S.universe?.setRecords([]);S.universeRecords=[];
  $('#application').hidden=true;$('#auth-view').hidden=false;
  $('#setup-field').hidden=!S.setup;$('#auth-form').elements.setupCode.required=S.setup;
  $('#auth-title').textContent=S.setup?'Set up administration':'Administrator or member sign-in';
  $('#auth-description').textContent=S.setup?'Browsing and learning are available without an account. Use the terminal setup code only to manage this instance or save private tools.':'Sign in to manage this instance or use saved watches and optional private package tools.';
  $('#auth-submit').textContent=S.setup?'Create administrator account':'Sign in';
  $('#auth-form').elements.password.autocomplete=S.setup?'new-password':'current-password';
  $('#browse-public').hidden=!S.public;
  $('#account-button').textContent='Administration';
  S.universe?.setVisible(false);
}
function appShell(){
  $('#application').hidden=false;$('#auth-view').hidden=true;
  $('#account-button').textContent=S.user?S.user.username:'Administration';
  $('#version').textContent=S.version||'';
  $('#collector-status').textContent='Collector: '+(S.syncMode==='embedded'?'running with this instance':S.syncMode==='external'?'external worker':'paused');
  $$('[data-auth-only]').forEach(el=>el.hidden=!S.user);
}
function pager(offset,count,total,action,size=100){
  return '<div class="pager"><span>'+num(total?offset+1:0)+'–'+num(offset+count)+' of '+num(total)+'</span><div><button type="button" class="small" data-action="'+action+'" data-offset="'+Math.max(0,offset-size)+'"'+(!offset?' disabled':'')+'>Previous</button><button type="button" class="small" data-action="'+action+'" data-offset="'+(offset+size)+'"'+(offset+count>=total?' disabled':'')+'>Next</button></div></div>';
}
function currentView(){const hash=location.hash.slice(1);return Object.hasOwn(viewInfo,hash)?hash:S.sharedToken?'highlights':'discover';}
function navigate(view){if($('#dialog').open)$('#dialog').close();if(location.hash==='#'+view)route();else location.hash=view;}
async function route(){
  const view=currentView();S.view=view;document.body.dataset.view=view;const epoch=++S.epoch;
  if(view!=='universe'){
    setUniverseControls(false);closeUniverseSelection();
    if(document.fullscreenElement===$('#universe-view'))document.exitFullscreen().catch(()=>{});
  }
  if(!S.user&&!(S.public&&(publicViews.includes(view)||(view==='highlights'&&S.sharedToken)))){showAuth();return;}
  appShell();$$('[data-view]').forEach(el=>{if(el.dataset.view===view)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current');});
  const info=viewInfo[view];$('#view-kicker').textContent=info[0];$('#view-title').textContent=info[1];$('#view-description').textContent=info[2];
  $('#view-actions').innerHTML=(view==='workspace'?button(icon('plus')+'Import software','import','primary'):
    view==='catalog'&&S.user?button('Check a package','package','primary'):
    view==='sources'&&S.user?.role==='admin'?button(icon('refresh')+'Refresh sources','sync','primary'):
    view==='watchlists'?button(icon('plus')+'Add watch','watch','primary'):'')+
    (!['settings','components'].includes(view)?button(icon('refresh')+'Refresh view','refresh','quiet'):'');
  $('#view').hidden=view==='universe';$('#universe-view').hidden=view!=='universe';S.universe?.setVisible(view==='universe');
  if(view!=='universe')$('#view').innerHTML='<p class="loading">Loading source records…</p>';
  try{await refreshView(epoch);}catch(error){if(error.name==='AbortError')return;if(epoch===S.epoch&&$('#auth-view').hidden){if(view==='universe')universeError(error);else $('#view').innerHTML=empty('This view could not load',message(error),button('Try again','refresh','primary'));}}
}
async function refreshView(epoch=S.epoch){
  const handlers={discover:loadDiscovery,learn:loadLearning,workspace:loadWorkspace,catalog:loadCatalog,components:loadComponents,changes:loadChanges,highlights:loadHighlights,watchlists:loadWatches,sources:loadSources,universe:loadUniverse,settings:loadSettings};
  await handlers[S.view](epoch);
}
function put(html,epoch){
  if(epoch!==S.epoch)return;
  const active=document.activeElement,formId=active?.form?.id,name=active?.name;
  const selection=active?.matches('input[type="search"],input[type="text"],input:not([type])')?[active.selectionStart,active.selectionEnd]:null;
  const expanded=new Set($$('#view details[open][data-event]').map(el=>el.dataset.event));
  $('#view').innerHTML=html;hydrateIcons($('#view'));
  $$('#view details[data-event]').forEach(el=>{if(expanded.has(el.dataset.event))el.open=true;});
  if(formId&&name){const replacement=document.getElementById(formId)?.elements.namedItem(name);if(replacement){replacement.focus({preventScroll:true});if(selection&&replacement.setSelectionRange)replacement.setSelectionRange(...selection);}}
}
function requestFor(view){S.requests[view]?.abort();const controller=new AbortController();S.requests[view]=controller;return controller;}
function currentRequest(view,controller,epoch){return epoch===S.epoch&&S.requests[view]===controller&&!controller.signal.aborted;}
async function loadDiscovery(epoch){
  const request=requestFor('discover');
  const data=await api('/api/catalog?sort=newest&limit=12',undefined,request.signal);
  if(!currentRequest('discover',request,epoch))return;
  S.discovery=data;S.revision=data.revision;put(discoveryMarkup(data),epoch);
}
async function loadLearning(epoch){
  if(S.learnRecord){put(learningMarkup(S.learnRecord,S.learnStep,{focus:S.learnFocus,checks:S.learnChecks}),epoch);return;}
  const request=requestFor('learn');
  const data=await api('/api/catalog?sort=newest&limit=1',undefined,request.signal);
  if(!currentRequest('learn',request,epoch))return;
  const selected=data.radar?.[0]||data.records[0];
  if(!selected){put(sourceStrip(data)+empty('The walkthrough opens with a collected CVE','Once the first records arrive, choose one in Discover, Intelligence, or the Universe and select Learn with this record.',button('Check collection progress','sources','primary')),epoch);return;}
  const detail=await api('/api/record?id='+encodeURIComponent(selected.id),undefined,request.signal);
  if(!currentRequest('learn',request,epoch))return;
  S.learnRecord=detail.record;S.learnStep=0;S.learnFocus=0;S.learnChecks=[];put(learningMarkup(S.learnRecord,0,{focus:0,checks:[]}),epoch);
}
async function loadWorkspace(epoch){
  const requests=[api('/api/inventories'),api('/api/findings?limit=100&offset='+S.findingOffset+'&resolved='+(S.resolved?'1':'0')+'&inventory='+encodeURIComponent(S.inventory))];
  if(S.inventory)requests.push(api('/api/inventories?id='+encodeURIComponent(S.inventory)));
  const [list,findings,detail]=await Promise.all(requests);
  if(epoch!==S.epoch)return;
  S.inventories=list.inventories;S.findings=findings.findings;S.inventoryDetail=detail||null;
  const inventories=list.inventories;
  const totals=[['Inventories',inventories.length],['Checked components',inventories.reduce((n,i)=>n+i.checked,0)],['Open findings',inventories.reduce((n,i)=>n+i.open,0)],['Incomplete scans',inventories.filter(i=>i.scan_state==='partial').length]];
  let html='<div class="stat-strip">'+totals.map(([label,value])=>'<div class="stat"><b>'+num(value)+'</b><span>'+label+'</span></div>').join('')+'</div>';
  if(!inventories.length){put(html+empty('Start with the software you use','Import a lockfile, manifest, or SBOM. MasterMonk will check its package versions with OSV and connect matches to exploitation evidence.',button('Import software','import','primary')),epoch);return;}
  html+='<form id="workspace-filters" class="toolbar"><label class="grow">Inventory<select name="inventory">'+opt('','All my inventories',S.inventory)+inventories.map(i=>opt(i.id,i.name,S.inventory)).join('')+'</select></label><label class="check"><input name="resolved" type="checkbox"'+(S.resolved?' checked':'')+'>Include resolved findings</label><button type="submit">Apply</button></form>';
  if(detail)html+=inventorySummary(detail);
  else html+='<div class="panel"><div class="split"><span>'+num(inventories.filter(i=>['queued','running'].includes(i.scan_state)).length)+' scans queued or running</span><span class="muted">Select an inventory for components, coverage, and scan controls.</span></div></div>';
  html+=findings.findings.length?findingTable(findings.findings):empty('No open matches in this view','Check the inventory’s scan status and coverage, or include resolved findings.');
  html+=pager(findings.offset,findings.findings.length,findings.total,'findings-page');
  put(html,epoch);
}
function inventorySummary(detail){
  const i=detail.inventory,finished=i.checked+i.skipped+i.errors,progress=i.components?Math.min(100,100*finished/i.components):0;
  const warnings=(i.metadata.warnings||[]).map(w=>'<p>'+esc(w)+'</p>').join('');
  const status=i.paused?'Paused':i.scan_state;
  let html='<section class="panel"><div class="split"><h2>'+esc(i.name)+'</h2><div class="button-row">'+pill(status,['complete'].includes(status)?'green':['partial'].includes(status)?'amber':'blue')+
    '<button type="button" data-action="scan" data-id="'+i.id+'"'+(['queued','running'].includes(i.scan_state)?' disabled':'')+'>Check now</button>'+
    '<button type="button" data-action="inventory-pause" data-id="'+i.id+'" data-mode="'+(i.paused?'resume':'pause')+'">'+(i.paused?'Resume':'Pause')+'</button>'+
    button('Replace manifest','replace')+button('Settings','inventory-settings','quiet')+'</div></div><div class="inventory-summary"><div><div class="progress" role="progressbar" aria-label="Components processed" aria-valuemin="0" aria-valuemax="'+i.components+'" aria-valuenow="'+finished+'"><span style="width:'+progress+'%"></span></div><p class="muted">'+num(i.checked)+' checked · '+num(i.pending)+' pending · '+num(i.errors)+' errors · '+num(i.skipped)+' skipped</p><p>'+esc(i.metadata.coverage)+'</p></div><dl class="inventory-meta"><dt>Last scan</dt><dd>'+date(i.last_scan,true)+'</dd><dt>Last complete scan</dt><dd>'+date(i.last_complete,true)+'</dd><dt>Internet exposure</dt><dd>'+(i.exposed?'Exposed':'Not marked exposed')+'</dd><dt>Asset importance</dt><dd>'+i.criticality+' / 5</dd></dl></div>';
  if(warnings)html+='<div class="notice warning">'+warnings+'</div>';
  if(S.syncMode==='off'||S.syncMode==='external')html+='<p class="muted">Queued work runs when your configured collector runs.</p>';
  html+='<details><summary>'+num(i.components)+' components · '+esc(i.source_kind)+'</summary><div class="table-scroll spaced"><table><thead><tr><th>Package</th><th>Version</th><th>Status</th><th>Evidence</th></tr></thead><tbody>'+
    detail.components.map(c=>'<tr><td class="finding-package">'+esc(c.name)+'<span class="subcell">'+esc(c.ecosystem)+'</span></td><td class="mono">'+esc(c.version||'Unresolved')+'</td><td>'+pill(c.status,c.status==='error'?'coral':c.status==='checked'?'green':'')+'<span class="subcell">'+esc(c.error||c.skipReason||'')+'</span></td><td>'+esc(c.evidence)+'<span class="subcell">'+esc((c.locations||[]).join(', '))+'</span></td></tr>').join('')+'</tbody></table></div>'+
    (i.components>detail.components.length?button('Browse all components','components','quiet'):'')+'</details><div class="button-row spaced"><a href="/api/inventory-export?id='+encodeURIComponent(i.id)+'">Export CycloneDX</a><button class="quiet" type="button" data-action="watch-inventory" data-id="'+i.id+'">Watch this inventory</button></div></section>';
  return html;
}
function findingTable(findings){
  return '<div class="table-scroll"><table><thead><tr><th>Installed package</th><th>Matching advisory</th><th>Priority</th><th>Exploitation</th><th>Publisher-reported fixes</th><th>Workflow</th></tr></thead><tbody>'+
    findings.map(f=>'<tr><td><span class="finding-package">'+esc(f.component.name)+'@'+esc(f.component.version)+'</span><span class="subcell">'+esc(f.component.ecosystem)+' · '+esc(f.inventory_name)+'</span></td>'+
      '<td><button type="button" class="record-button" data-finding="'+f.id+'"><span class="record-id">'+esc(f.advisoryId)+'</span><strong>'+esc(f.title)+'</strong></button><span class="subcell">'+severityPill(f)+'</span></td>'+
      '<td>'+priorityMarkup(f)+'</td><td>'+(f.kev?pill('CISA KEV','coral'):'<span class="muted">Not listed in saved KEV</span>')+'<span class="subcell">EPSS '+percent(f.epss)+'</span></td>'+
      '<td class="mono">'+esc(f.fixedVersions.length?f.fixedVersions.slice(0,5).join(', '):'Not supplied')+(f.fixedVersions.length>5?'<span class="subcell">Open evidence for all ranges</span>':'')+'</td>'+
      '<td>'+pill(f.status,f.status==='resolved'?'green':'')+'<span class="subcell">'+age(f.last_seen)+'</span></td></tr>').join('')+'</tbody></table></div>';
}
async function loadCatalog(epoch){
  const c={...S.catalog},request=requestFor('catalog');
  const data=await api('/api/catalog?'+new URLSearchParams({q:c.q,severity:c.severity,kev:c.kev?'1':'0',days:c.days,sort:c.sort,limit:'100',offset:String(c.offset)}),undefined,request.signal);
  if(!currentRequest('catalog',request,epoch))return;S.catalogData=data;S.revision=data.revision;
  let html='<div class="stat-strip">'+[['Collected records',data.stats.total],['Known exploited',data.stats.kev],['CVSS ≥ 9',data.stats.critical],['Published this week',data.stats.newWeek]].map(([k,v])=>'<div class="stat"><b>'+num(v)+'</b><span>'+k+'</span></div>').join('')+'</div>';
  html+='<form id="catalog-filters" class="toolbar"><label class="grow">Search<input name="q" type="search" value="'+esc(c.q)+'" placeholder="CVE, vendor, product, or package"></label><label>Severity<select name="severity">'+['all','Critical','High','Medium','Low','None','Unknown'].map(x=>opt(x,x==='all'?'All severities':x,c.severity)).join('')+'</select></label><label>Published<select name="days">'+[['0','Any time'],['7','Past week'],['30','Past month'],['90','Past 90 days'],['365','Past year']].map(([v,l])=>opt(v,l,c.days)).join('')+'</select></label><label>Sort<select name="sort">'+[['priority','Priority'],['newest','Newest'],['cvss','CVSS'],['epss','EPSS']].map(([v,l])=>opt(v,l,c.sort)).join('')+'</select></label><label class="check"><input type="checkbox" name="kev"'+(c.kev?' checked':'')+'>KEV only</label><button type="submit" class="primary">Search</button></form>';
  if(S.user)html+='<div class="toolbar"><label class="grow">Saved filters<select id="saved-filter"><option value="">Choose a saved filter</option>'+S.profile.filters.map((f,i)=>opt(i,f.name,'')).join('')+'</select></label>'+button('Save current filter','save-filter','quiet')+'<a href="/api/export?format=csv">Export catalog CSV</a></div>';
  if(!data.stats.total)html+=empty('Your catalog is waiting for its first import','Check Sources for collection progress. Records will appear as providers respond.',button('View sources','sources','primary'));
  else html+='<p class="muted">'+num(data.matching)+' matching records · '+(c.severity==='all'?'All severities':esc(c.severity))+(c.kev?' · KEV only':'')+'</p>'+(data.records.length?recordTable(data.records)+pager(data.offset,data.records.length,data.matching,'catalog-page'):empty('No records match these filters','Clear the search or choose another severity. You can also look up a published CVE directly from Discover.',button('Clear filters','clear-filters','primary')));
  html+='<p class="muted"><small>Last successful collection: '+date(data.lastSuccess,true)+' · History starts '+date(data.baseline)+'.</small></p>';
  put(html,epoch);
}
async function loadComponents(epoch){
  put(componentComparisonView(S.componentComparison,location.origin),epoch);
}
async function loadChanges(epoch){
  const request=requestFor('changes');
  const [trends,events]=await Promise.all([api('/api/trends?'+new URLSearchParams({days:String(S.trendDays),basis:S.trendBasis}),undefined,request.signal),api('/api/events',undefined,request.signal)]);
  if(!currentRequest('changes',request,epoch))return;S.trends=trends;
  S.events=[...new Map([...events.events,...S.events].map(event=>[event.id,event])).values()].sort((a,b)=>b.id-a.id).slice(0,1000);
  renderChanges(epoch);
}
const trendSeries={
  source:[['published','Published disclosures','#4a88c2'],['critical','Critical published','#8d60bf'],['modified','Publisher updates','#b67a25'],['kevAdded','CISA KEV additions','#d64849']],
  observed:[['indexed','First indexed locally','#4a88c2'],['changed','Evidence updates','#b67a25'],['kevAdded','Observed KEV additions','#d64849'],['remediation','Remediation changes','#378a77']]
};
function aggregateTrend(days,requested){
  if(requested<=30)return days.map(day=>({...day,start:day.date,end:day.date,label:day.date}));
  const keys=Object.keys(days[0]||{}).filter(key=>!['date'].includes(key));
  if(requested<=90){const groups=[];for(let i=0;i<days.length;i+=7){const slice=days.slice(i,i+7),point={start:slice[0].date,end:slice.at(-1).date,label:slice[0].date+' – '+slice.at(-1).date};for(const key of keys)point[key]=slice.reduce((sum,day)=>sum+(Number(day[key])||0),0);groups.push(point);}return groups;}
  const groups=new Map();for(const day of days){const month=day.date.slice(0,7);if(!groups.has(month))groups.set(month,{start:day.date,end:day.date,label:month});const point=groups.get(month);point.end=day.date;for(const key of keys)point[key]=(point[key]||0)+(Number(day[key])||0);}return [...groups.values()];
}
function renderChanges(epoch){
  const data=S.trends,series=trendSeries[data.basis],points=aggregateTrend(data.days,data.requestedDays),active=data.days.filter(day=>series.some(([key])=>day[key]>0));
  const coverage=data.basis==='source'?'Uses publication and modification dates reported by collected providers.':'This installation has '+num(data.days.length)+' day'+(data.days.length===1?'':'s')+' of local observation history, beginning '+date(data.availableFrom)+'.';
  let html='<section class="change-command"><div class="change-coverage"><div><span class="kicker">'+(data.basis==='source'?'PROVIDER TIMELINE':'LOCAL OBSERVATION TIMELINE')+'</span><h2>'+esc(data.rangeFrom)+' → '+esc(data.rangeTo)+'</h2><p>'+coverage+'</p></div><form id="trend-filters" class="toolbar"><label>Timeline<select name="basis">'+opt('source','Published by sources',S.trendBasis)+opt('observed','Observed by MasterMonk',S.trendBasis)+'</select></label><label>Period<select name="days">'+[7,30,90,365].map(d=>opt(d,d+' days',S.trendDays)).join('')+'</select></label><button type="submit">Apply</button></form></div>'+
    '<div class="change-stats">'+series.map(([key,label,color])=>'<div style="--series:'+color+'"><span>'+esc(label)+'</span><strong>'+num(data.totals[key]||0)+'</strong></div>').join('')+'</div>'+activityChart(points,series)+
    '<div class="activity-periods">'+activityPeriods(points,series,data.basis)+'</div>'+
    (active.length?'<details class="activity-table"><summary>View dates with recorded activity</summary><div class="table-scroll spaced"><table><thead><tr><th>Date</th>'+series.map(([,label])=>'<th>'+esc(label)+'</th>').join('')+'</tr></thead><tbody>'+active.slice().reverse().map(day=>'<tr><td>'+esc(day.date)+'</td>'+series.map(([key])=>'<td>'+num(day[key])+'</td>').join('')+'</tr>').join('')+'</tbody></table></div></details>':'')+'</section>';
  html+=comparisonForm(S.comparison)+'<section class="panel saved-change-stream"><div class="section-heading"><div><span class="kicker">SAVED BY THIS INSTANCE</span><h2>Evidence change stream</h2></div></div>'+(S.events.length?S.events.map(eventMarkup).join('')+button('Load earlier changes','older-events','quiet spaced'):empty('No later evidence changes saved yet','The first collection establishes a baseline. Later provider differences will appear here.'))+'</section>';
  put(html,epoch);
}
async function loadHighlights(epoch){
  if(S.sharedToken){
    const page=await api('/api/highlight?token='+encodeURIComponent(S.sharedToken));
    put('<div class="button-row">'+(S.user?button('Manage my highlights','highlights-manage','quiet'):'')+'<button type="button" data-action="highlight-copy" data-token="'+esc(page.token)+'">Copy link</button></div>'+highlightPage(page),epoch);
  }else{
    const data=await api('/api/highlights');put(highlightComposer(S.highlightDraft,data.highlights),epoch);
  }
}
function highlightURL(token){const url=new URL(location.pathname,location.origin);url.searchParams.set('highlight',token);url.hash='highlights';return url.href;}
function rememberHighlightDraft(){
  const form=$('#highlight-form');if(!form)return;
  S.highlightDraft.title=form.elements.title.value;S.highlightDraft.note=form.elements.note.value;
  for(const input of form.querySelectorAll('[data-highlight-id]')){const item=S.highlightDraft.items.find(r=>r.id===input.dataset.highlightId);if(item)item.note=input.value;}
}
function activityChart(points,series){
  const maximum=Math.max(0,...points.flatMap(point=>series.map(([key])=>Number(point[key])||0)));
  if(!maximum)return '<div class="trend-empty"><span class="kicker">NO MATCHING EVENTS</span><h3>No activity for this period</h3><p>Choose the provider timeline, another period, or wait for a later collection cycle. Missing history is not filled with generated counts.</p></div>';
  const width=1050,height=270,left=58,right=20,top=18,bottom=48,available=width-left-right,slot=available/points.length;
  const rough=Math.max(1,maximum/4),power=10**Math.floor(Math.log10(rough)),normalized=rough/power;
  const tickStep=Math.max(1,(normalized<=1?1:normalized<=2?2:normalized<=5?5:10)*power),topValue=Math.ceil(maximum/tickStep)*tickStep;
  const y=value=>height-bottom-(height-top-bottom)*value/topValue,barWidth=Math.max(.75,Math.min(8,slot/(series.length+1))),groupWidth=barWidth*series.length;
  let svg='<svg class="trend-chart" role="img" aria-label="Activity counts for the selected time period" viewBox="0 0 '+width+' '+height+'">';
  for(let value=0;value<=topValue;value+=tickStep)svg+='<line class="grid" x1="'+left+'" y1="'+y(value)+'" x2="'+(width-right)+'" y2="'+y(value)+'"/><text text-anchor="end" x="'+(left-9)+'" y="'+(y(value)+4)+'">'+num(value)+'</text>';
  points.forEach((point,index)=>series.forEach(([key,label,color],seriesIndex)=>{const value=Number(point[key])||0;if(!value)return;const x=left+(index+.5)*slot-groupWidth/2+seriesIndex*barWidth;svg+='<rect x="'+x+'" y="'+y(value)+'" width="'+Math.max(.7,barWidth-1)+'" height="'+(height-bottom-y(value))+'" rx="1" fill="'+color+'"><title>'+esc(point.label)+' · '+esc(label)+': '+num(value)+'</title></rect>';}));
  if(points.length)[0,Math.floor((points.length-1)/2),points.length-1].forEach((index,labelIndex)=>{svg+='<text text-anchor="'+(labelIndex===0?'start':labelIndex===2?'end':'middle')+'" x="'+(left+(index+.5)*slot)+'" y="'+(height-15)+'">'+esc(points[index].label)+'</text>';});
  svg+='</svg><div class="trend-legend">'+series.map(([,label,color])=>'<span><i style="background:'+color+'"></i>'+esc(label)+'</span>').join('')+'</div>';return svg;
}
function activityPeriods(points,series,basis){
  const active=points.filter(point=>series.some(([key])=>point[key]>0)).slice().reverse().slice(0,12);
  if(!active.length)return '';
  return '<div class="section-heading"><div><span class="kicker">OPEN THE RECORDS</span><h3>Investigate active periods</h3></div></div><div class="activity-grid">'+active.map(point=>'<article><strong>'+esc(point.label)+'</strong><div>'+series.filter(([key])=>point[key]>0).map(([key,label])=>'<button type="button" data-action="trend-period" data-basis="'+basis+'" data-metric="'+key+'" data-start="'+point.start+'" data-end="'+point.end+'">'+num(point[key])+' '+esc(label)+'</button>').join('')+'</div></article>').join('')+'</div>';
}
async function openTrendPeriod(el){
  const series=trendSeries[el.dataset.basis]||[],label=series.find(([key])=>key===el.dataset.metric)?.[1]||'Activity';
  openDialog(label+' · '+el.dataset.start+(el.dataset.start===el.dataset.end?'':' to '+el.dataset.end),'<p class="loading">Loading the collected records…</p>');
  const epoch=S.dialogEpoch,data=await api('/api/trend-records?'+new URLSearchParams({basis:el.dataset.basis,metric:el.dataset.metric,start:el.dataset.start,end:el.dataset.end,limit:'100'}));
  if(!$('#dialog').open||epoch!==S.dialogEpoch)return;
  $('#dialog-content').innerHTML=data.records.length?recordTable(data.records)+(data.truncated?'<p class="muted spaced">First 100 records shown. Narrow the period to inspect a smaller set.</p>':''):empty('No records remain in this activity period','Refresh the view if the underlying catalog changed.');
  hydrateIcons($('#dialog-content'));
}
async function loadWatches(epoch){
  const [inbox,rules,list]=await Promise.all([api('/api/alerts?offset='+S.inboxOffset),api('/api/watch-rules'),api('/api/inventories')]);
  if(epoch!==S.epoch)return;S.inventories=list.inventories;S.rules=rules.rules;S.inbox=inbox;
  $('#unread-count').textContent=num(inbox.unread);$('#unread-count').hidden=!inbox.unread;
  let html='<div class="split-panels"><section class="panel"><div class="split"><h2>Inbox</h2><div class="button-row">'+button('Mark all read','read-alerts','quiet')+button('Atom feed link','feed','quiet')+'</div></div>';
  html+=inbox.alerts.length?inbox.alerts.map(a=>'<article class="list-row"><div><div class="button-row">'+(!a.read?pill('New','coral'):'')+'<button class="record-button" type="button" data-record="'+esc(a.payload.id)+'"><span class="record-id">'+esc(a.payload.id)+'</span><strong>'+esc(a.payload.title)+'</strong></button></div><p>'+esc(a.payload.reasons.join(' · '))+'</p><p class="muted">'+esc(a.payload.watch)+(a.payload.package?' · '+esc(a.payload.package)+'@'+esc(a.payload.version):'')+' · '+date(a.created,true)+'</p>'+(a.delivery?.length?a.delivery.map(d=>'<p>'+pill(d.status,d.status==='failed'?'coral':'')+' '+esc(d.error||'')+'</p>').join(''):'')+'</div></article>').join(''):empty('You’re up to date','New matches and threshold crossings from your watches will appear here.');
  html+=pager(S.inboxOffset,inbox.alerts.length,inbox.total,'inbox-page',100)+'</section><section class="panel"><h2>Watch rules</h2>';
  html+=rules.rules.length?rules.rules.map(r=>'<article class="list-row"><div><h3>'+esc(r.name)+'</h3><p>'+esc(r.scope)+' · '+esc(r.selector||'All my inventories')+'</p><p class="muted">'+esc(r.trigger)+' · threshold '+r.threshold+' · '+esc(r.channel)+'</p>'+(!r.enabled?pill('Paused'):'')+(r.error?'<p class="danger-text">'+esc(r.error)+'</p>':'')+'</div><div class="button-row"><button class="small" type="button" data-action="watch-toggle" data-id="'+r.id+'" data-mode="'+(r.enabled?'pause':'resume')+'">'+(r.enabled?'Pause':'Resume')+'</button><button class="small danger" type="button" data-action="watch-delete" data-id="'+r.id+'">Delete</button></div></article>').join(''):empty('Follow what matters','Watch an inventory, vendor, product, package, or specific vulnerability.',button('Add watch','watch','primary'));
  html+='<p class="muted spaced"><small>A new watch starts from the current evidence. Notifications follow new matches or later threshold crossings.</small></p></section></div>';
  put(html,epoch);
}
async function loadSources(epoch){
  const data=await api('/api/sources');if(epoch!==S.epoch)return;S.sources=data;
  let html='<section class="panel"><div class="split"><h2>Intelligence feeds</h2><span class="muted">Collector heartbeat: '+age(data.workerHeartbeat)+'</span></div>'+
    data.sources.map(s=>'<article class="list-row"><div><span class="source-state '+esc(s.state)+'">'+esc(s.state)+'</span><strong class="source-name">'+esc(sourceNames[s.id]||s.id)+'</strong><p>'+esc(s.message||'')+'</p>'+(s.coverage?'<p class="muted">'+esc(s.coverage)+'</p>':'')+(s.retryAt?'<p class="muted">Retry after '+date(s.retryAt,true)+'</p>':'')+'</div><div class="source-freshness"><strong>'+num(s.count)+'</strong><span class="subcell">Last success<br>'+date(s.lastSuccess,true)+'</span></div></article>').join('')+'</section>';
  const ep=data.epss||{};
  html+='<div class="split-panels"><section class="panel"><h2>Daily EPSS coverage</h2><p>The daily FIRST snapshot updates all matching CVEs in your catalog.</p><dl class="inventory-meta"><dt>Snapshot date</dt><dd>'+esc(ep.date||ep.scoreDate||'Not fetched')+'</dd><dt>Current tracked CVEs</dt><dd>'+num(ep.current)+'</dd><dt>Tracked CVEs</dt><dd>'+num(ep.tracked)+'</dd><dt>Not in snapshot</dt><dd>'+num(ep.notSupplied)+'</dd></dl></section>';
  const b=data.backfill;
  html+='<section class="panel"><div class="split"><h2>Historical NVD import</h2>'+pill(b.complete?'Complete':b.enabled?'Enabled':'Paused')+'</div><p>Import earlier CVEs in saved date windows. Progress resumes after restarts.</p><dl class="inventory-meta"><dt>Pages saved</dt><dd>'+num(b.pages||0)+'</dd><dt>Records processed</dt><dd>'+num(b.imported||0)+'</dd><dt>Current window</dt><dd>'+date(b.windowStart)+'</dd><dt>Last page saved</dt><dd>'+date(b.lastSuccess,true)+'</dd></dl>'+(b.error?'<p class="notice error">'+esc(b.error)+'</p>':'');
  if(S.user?.role==='admin')html+='<div class="button-row spaced">'+(b.enabled?'<button type="button" data-action="backfill" data-mode="pause">Pause import</button>':b.complete?'<button type="button" data-action="backfill" data-mode="restart">Start a new pass</button>':'<button type="button" data-action="backfill" data-mode="'+(b.generation?'resume':'start')+'">'+(b.generation?'Resume import':'Start historical import')+'</button>')+'</div>';
  html+='</section></div>';
  if(S.user)html+='<section class="panel"><div class="split"><h2>Vendor advisories & VEX</h2>'+button('Connect a publisher','vendor','primary')+'</div><p class="muted">Import CSAF or OpenVEX JSON, or follow a publisher’s HTTPS feed.</p>'+
    (data.vendorSources.length?data.vendorSources.map(v=>'<article class="list-row"><div><h3>'+esc(v.name)+'</h3><p>'+esc(v.kind)+' · '+(v.trusted?'Trusted by you':'Trust not established')+' · '+age(v.last_fetch)+'</p>'+(v.error?'<p class="danger-text">'+esc(v.error)+'</p>':'')+'</div><div class="button-row"><button type="button" class="small" data-action="vendor-statements" data-id="'+v.id+'">Statements</button>'+(v.kind==='url'?'<button type="button" class="small" data-action="vendor-refresh" data-id="'+v.id+'">Refresh</button><button type="button" class="small" data-action="vendor-toggle" data-id="'+v.id+'" data-mode="'+(v.enabled?'pause':'resume')+'">'+(v.enabled?'Pause':'Resume')+'</button>':'')+'<button type="button" class="small danger" data-action="vendor-delete" data-id="'+v.id+'">Delete</button></div></article>').join(''):empty('No vendor connectors yet','Connect a publisher or upload a vendor document to add applicability statements to matching evidence.'))+'</section>';
  put(html,epoch);
}
async function loadSettings(epoch){
  const requests=[api('/api/profile'),api('/api/tokens')];if(S.user.role==='admin')requests.push(api('/api/users'));
  const [profile,tokens,users]=await Promise.all(requests);if(epoch!==S.epoch)return;S.profile=profile;
  let html='<section class="panel"><h2>Optional tools</h2><p>Discover, Universe, Intelligence, Changes, Sources, and Learn use the public vulnerability catalog. These extra tools are available when you need them.</p><div class="button-row"><a class="button-link" href="#watchlists">Saved watches</a><a class="button-link" href="#workspace">Private package inventories</a>'+button('Check one package','package')+'</div></section><section class="panel"><h2>Priority weights</h2><p class="muted">Choose how much each signal contributes. Scores are capped at 100; each record shows its calculation.</p><form id="weights-form">'+Object.entries(profile.weights).map(([key,value])=>'<div class="weight-row"><label for="weight-'+key+'">'+labels[key]+'</label><input id="weight-'+key+'" type="range" name="'+key+'" min="0" max="100" step="1" value="'+value+'" aria-label="'+labels[key]+' weight"><output for="weight-'+key+'">'+value+'</output></div>').join('')+'<p class="form-error" role="alert"></p><div class="button-row spaced"><button type="submit" class="primary">Save priority weights</button></div></form></section>';
  html+='<div class="split-panels"><section class="panel"><div class="split"><h2>API tokens</h2>'+button('Create token','token','primary')+'</div><p class="muted">Use scoped, expiring tokens in CI. The full token is shown once.</p>'+
    (tokens.tokens.length?tokens.tokens.map(t=>'<div class="list-row"><div><strong>'+esc(t.name)+'</strong><span class="subcell">'+esc(t.scopes.join(', '))+' · expires '+date(t.expires*1000)+'</span></div><button type="button" class="small danger" data-action="revoke-token" data-digest="'+t.digest+'">Revoke</button></div>').join(''):'<p>No API tokens created.</p>')+
    '<details class="spaced"><summary>Command-line checks</summary><pre>python mastermonk.py check PATH_TO_MANIFEST --fail-on kev\npython mastermonk.py check PATH_TO_MANIFEST --fail-on high --format sarif --output findings.sarif</pre><p class="muted">Exit codes: 0 passes, 1 has policy violations, 2 is incomplete. Supply your actual manifest or SBOM path.</p></details></section>';
  html+='<section class="panel"><h2>Account</h2><p>Signed in as <strong>'+esc(S.user.username)+'</strong> · '+esc(S.user.role)+'</p>'+button('Change password','password')+button('Sign out','logout','quiet')+
    '<h3 class="spaced">Saved filters</h3>'+(profile.filters.length?profile.filters.map((f,i)=>'<div class="list-row"><span>'+esc(f.name)+'</span><button class="small danger" type="button" data-action="delete-filter" data-index="'+i+'">Remove</button></div>').join(''):'<p class="muted">Save a search from Intelligence to return to it quickly.</p>')+'</section></div>';
  if(users)html+='<section class="panel"><div class="split"><h2>People</h2>'+button('Add member','add-user','primary')+'</div><div class="table-scroll spaced"><table><thead><tr><th>Username</th><th>Role</th><th>Access</th><th>Action</th></tr></thead><tbody>'+users.users.map(u=>'<tr><td>'+esc(u.username)+'</td><td>'+esc(u.role)+'</td><td>'+pill(u.disabled?'Disabled':'Active',u.disabled?'':'green')+'</td><td>'+(!u.disabled&&u.id!==S.user.id?'<button class="small danger" type="button" data-action="disable-user" data-id="'+u.id+'" data-name="'+esc(u.username)+'">Disable</button>':'—')+'</td></tr>').join('')+'</tbody></table></div><p class="muted spaced">Members share public intelligence. Their inventories, saved filters, and watches remain private.</p></section>';
  put(html,epoch);
}
function updateUniverseLiveStatus(data={}){
  const allSources=Array.isArray(data.sources)?data.sources:[];
  const scheduled=allSources.filter(source=>!['cve','osv'].includes(source.id));
  const responded=scheduled.filter(source=>source.lastSuccess).length;
  const failed=scheduled.filter(source=>source.state==='error').length;
  const sync=data.sync||{};
  const beacon=$('#universe-feed-beacon'),state=$('#universe-live-state'),detail=$('#universe-live-detail');
  if(!beacon||!state||!detail)return;
  let mode='waiting';
  if(sync.running){mode='running';state.textContent='Collecting public-source updates';detail.textContent='Started '+age(sync.startedAt);}
  else if(failed){mode='error';state.textContent=failed+' scheduled feed'+(failed===1?' needs':'s need')+' attention';detail.textContent=(data.lastSuccess?'Last successful save '+age(data.lastSuccess):'No successful collection yet');}
  else if(data.lastSuccess){mode='ok';state.textContent=responded+'/'+scheduled.length+' scheduled feeds have responded';detail.textContent='Last saved '+age(data.lastSuccess)+(sync.nextAt?' · next check '+date(sync.nextAt,true):'');}
  else {state.textContent='Waiting for the first source response';detail.textContent=S.syncMode==='off'?'Automatic collection is paused':'Collector state is available in the instrument drawer';}
  beacon.className='cosmos-beacon '+mode;
}
function setUniverseControls(open){
  const panel=$('#universe-control-panel'),button=$('#universe-controls-button');if(!panel||!button)return;
  const active=!!open;panel.classList.toggle('is-open',active);panel.setAttribute('aria-hidden',String(!active));panel.toggleAttribute('inert',!active);button.setAttribute('aria-expanded',String(active));
  if(active&&window.innerWidth<900)closeUniverseSelection();
}
function closeUniverseSelection(){
  const panel=$('#universe-selection');if(!panel)return;
  $('.cosmos-shell .universe-stage')?.classList.remove('has-evidence-drawer');
  panel.classList.remove('is-open');
  setTimeout(()=>{if(!panel.classList.contains('is-open'))panel.hidden=true;},330);
}
async function loadUniverse(epoch){
  const form=$('#universe-filters'),q=form.elements.q.value.trim(),level=form.elements.severity.value,kev=form.elements.kev.checked,group=form.elements.group.value;
  const key=JSON.stringify([q,level,kev,group]),changed=key!==S.universeFilterKey,request=requestFor('universe');
  S.universeFilterKey=key;
  $('#universe-error').hidden=true;
  $('#universe-view').setAttribute('aria-busy','true');
  if(changed){S.universe?.setRecords([]);S.universeRecords=[];$('#universe-selection').hidden=true;$('#universe-table').replaceChildren();$('#universe-empty').hidden=true;}
  $('#universe-meta').textContent='Applying '+(level==='all'?'all severities':level)+(kev?' · KEV only':'')+'…';
  try{
    const [data,events]=await Promise.all([
      api('/api/universe?'+new URLSearchParams({limit:'10000',q,severity:level,kev:kev?'1':'0'}),undefined,request.signal),
      api('/api/events',undefined,request.signal)
    ]);
    if(!currentRequest('universe',request,epoch))return;
    if(!S.universe){
      const {Universe}=await import('./universe.js');if(!currentRequest('universe',request,epoch))return;
      S.universe=new Universe($('#universe'),$('#universe-tooltip'),selectUniverse,paused=>$('#motion-button').textContent=paused?'Resume motion':'Pause motion',status=>{
        S.renderer=status;
        const names={low:'SURVEY',balanced:'ORBITAL',cinematic:'DEEP FIELD',canvas:'CANVAS'};
        const presentation=rendererPresentation(status);$('#renderer-state').textContent=presentation.label+(status.mode==='webgl'?' · '+(names[status.quality]||'3D'):'');
        $('#universe-view').dataset.quality=status.mode==='webgl'?status.quality:'canvas';
        $('.cosmos-orientation').hidden=status.mode!=='webgl';
        $('#renderer-notice').textContent=presentation.notice;$('#renderer-notice').hidden=!presentation.notice;
        $('#renderer-notice').className='cosmos-notice'+(presentation.warning?' warning':'');
        $('#graphics-quality').value=status.quality||'canvas';
        $('#universe-encoding').textContent=status.mode!=='webgl'?'Canvas: severity color · CVSS size · CISA KEV outline':status.quality==='low'?'Survey: faceted severity cores · CVSS size · KEV orbits · clear field':status.quality==='cinematic'?'Deep field: faceted cores · available EPSS coronas · denser 3D clouds and bloom':'Orbital: faceted cores · EPSS ≥ 5% coronas · light 3D clouds and glow';
      });
      $('#graphics-quality').value=S.universe.quality;
    }
    const records=data.records;updateUniverseLiveStatus(data);
    const fresh=!changed&&S.universeBaseline?records.filter(r=>!S.universeKnown.has(r.id)&&Date.parse(r.firstObserved)>S.universeBaseline&&Date.parse(r.firstObserved)<=Date.now()).map(r=>r.id):[];
    if(!S.universeBaseline&&records.length)S.universeBaseline=Date.now();
    records.forEach(r=>S.universeKnown.add(r.id));
    S.universeRecords=records;S.revision=data.revision;S.universe.setRecords(records,group);S.universe.setHighlights(events.events);S.universe.setNewRecords(fresh);S.universe.setVisible(!$('#dialog').open);
    if(S.universe.selected&&!$('.cosmos-shell .universe-stage').classList.contains('is-warping'))selectUniverse(S.universe.selected);
    $('#universe-meta').textContent=num(records.length)+' of '+num(data.matching)+' matching records · '+(level==='all'?'All severities':level)+(kev?' · KEV only':'')+(q?' · Search: '+q:'')+' · grouped by '+({vendor:'company',weakness:'weakness type',severity:'severity',source:'collected source'}[group]);
    $('#universe-table').innerHTML=recordTable(records.slice(0,100))+(records.length>100?'<p class="muted">First 100 records shown here. Narrow your search or open Intelligence to page through all results.</p>':'');
    $('#motion-button').textContent=S.universe.paused?'Resume motion':'Pause motion';
    $('#universe-empty').hidden=records.length>0;
    $('#universe-empty').textContent=data.stats.total?'No collected records match these filters. Choose another severity or clear the search.':'Waiting for the first source records. Collection progress is available in Sources; this view updates automatically.';
    if(!records.length)$('#universe-selection').hidden=true;
    $('#universe-view').setAttribute('aria-busy','false');
  }catch(error){
    if(error.name==='AbortError'||!currentRequest('universe',request,epoch))return;
    universeError(error);
  }
}
function universeError(error){
  S.universe?.setRecords([]);S.universeRecords=[];$('#universe-table').replaceChildren();$('#universe-selection').hidden=true;
  $('#universe-meta').textContent='The selected filter could not be loaded.';
  $('#universe-error').textContent=message(error);$('#universe-error').hidden=false;
  $('#universe-view').setAttribute('aria-busy','false');
}
function selectUniverse(id){
  const record=S.universeRecords.find(r=>r.id===id),el=$('#universe-selection');
  $('.cosmos-touch-pad').hidden=!record;
  if(!record){closeUniverseSelection();return;}
  setUniverseControls(false);el.hidden=false;
  $('.cosmos-shell .universe-stage').classList.add('has-evidence-drawer');
  const sources=(record.sourceIds||[]).map(id=>sourceNames[id]||id).join(' · ')||'No source labels supplied';
  el.innerHTML='<header class="cosmos-evidence-head"><div><span class="cosmos-evidence-id">'+esc(record.id)+'</span><h2>'+esc(record.title)+'</h2></div><button type="button" class="cosmos-close" data-action="universe-selection-close" aria-label="Close selected record">×</button></header><div class="cosmos-evidence-body"><div class="cosmos-evidence-metrics"><div><span>Severity</span><strong>'+esc(record.severity||'Unknown')+'</strong></div><div><span>CVSS</span><strong>'+metric(record.cvss)+'</strong></div><div><span>EPSS</span><strong>'+percent(record.epss)+'</strong></div></div><p class="universe-sources">'+(S.renderer?.mode==='webgl'?'Orbiting collected providers: ':'Collected providers: ')+esc(sources)+'</p><p class="universe-sources">CISA KEV: '+(record.kev?'Observed in the saved KEV catalog':'Not observed in the saved KEV catalog')+'</p><p class="cosmos-investigate-prompt">YOU’RE AT THE RECORD · Where do you want to go next?</p><div class="button-row"><button type="button" data-record="'+esc(record.id)+'">Investigate evidence</button><button type="button" data-action="learn-record" data-id="'+esc(record.id)+'">Open investigation lab</button>'+(S.user?'<button type="button" data-action="highlight-add" data-id="'+esc(record.id)+'">Add to highlights</button>':'')+'</div><p class="cosmos-gesture-tip">One finger or mouse drag to orbit · pinch to zoom · use the arrow pad for precise movement.</p></div>';
  requestAnimationFrame(()=>el.classList.add('is-open'));
}
async function toggleUniverseFullscreen(){
  const view=$('#universe-view');
  if(document.fullscreenElement){await document.exitFullscreen();return;}
  if(!view.requestFullscreen)throw new Error('Fullscreen is not available in this browser.');
  await view.requestFullscreen();
}
function priorities(value){
  if(!value)return '';
  return '<h3>Why this priority?</h3><div class="table-scroll"><table><thead><tr><th>Signal</th><th>Weight</th><th>Contribution</th></tr></thead><tbody>'+
    (value.reasons||[]).map(r=>'<tr><td>'+esc(r.label)+'</td><td>'+num(r.weight)+'</td><td>'+num(r.points)+'</td></tr>').join('')+'</tbody></table></div>'+
    '<p class="muted spaced">Score '+num(value.score)+' / 100 · '+esc(value.band)+(value.missing?.length?' · Missing: '+esc(value.missing.join(', ')):'')+(value.rawScore>100?' · Uncapped total '+num(value.rawScore):'')+'</p>';
}
function sourceList(record){
  return '<ul class="reference-list">'+(record?.sources||[]).map(s=>'<li>'+link(s.url,sourceNames[s.id]||s.id)+'<span class="subcell">Observed '+date(s.observedAt,true)+(s.modified?' · publisher update '+date(s.modified,true):'')+'</span></li>').join('')+'</ul>';
}
function statementsHTML(statements){
  if(!statements.length)return '<p class="muted">No imported vendor statements match this evidence.</p>';
  return statements.map(s=>'<article class="panel"><div class="split"><h3>'+esc(s.vulnerability)+'</h3>'+pill(s.status.replaceAll('_',' '),s.status==='not_affected'?'blue':'')+'</div><p class="subcell">'+esc(s.document?.issuer||s.sourceName||'Publisher document')+'</p><p>'+esc(s.justification||s.impact||'')+'</p>'+
    (s.actions||[]).map(a=>'<p>'+esc(a.details)+(a.url?' '+link(a.url,'Remediation source'):'')+'</p>').join('')+'<p class="muted">'+esc(s.purl||s.product||'')+'</p><p class="muted">Issued '+date(s.document?.issued)+' · '+(s.trusted?'Trusted by you':'Trust not established')+(s.contextPurl?(s.contextMatches?' · Product context matches':' · Different product context'):'')+'</p>'+
    (s.document?.url?link(s.document.url,'Publisher document'):'<span class="muted">Uploaded publisher document</span>')+'</article>').join('')+
    '<p class="muted"><small>Vendor statements annotate the evidence. They do not automatically close or suppress a finding.</small></p>';
}
async function showRecord(identifier){
  openDialog(identifier,'<p class="loading">Loading source evidence…</p>');
  S.evidence=null;S.record=null;S.recordTab='overview';const epoch=S.dialogEpoch;
  try{
    const data=await api('/api/record?id='+encodeURIComponent(identifier));
    if(!$('#dialog').open||epoch!==S.dialogEpoch)return;
    S.record=data.record;S.recordStatements=data.statements||[];
    $('#dialog-title').textContent=S.record.id;
    const tabs=[['overview','Overview'],['evidence','Sources & evidence'],['packages','Affected software & fixes'],['graph','3D evidence graph'],['patterns','Weakness & techniques'],['history','Saved history'],['ai','AI reading aid']];
    $('#dialog-content').innerHTML=recordSummary(S.record)+'<nav class="record-tabs" aria-label="Investigation sections">'+tabs.map(([key,label])=>'<button type="button" data-action="record-tab" data-tab="'+key+'" aria-pressed="'+(key==='overview')+'">'+label+'</button>').join('')+'</nav><div id="record-tab-content"></div><div class="dialog-footer"><button type="button" data-action="learn-record" data-id="'+esc(S.record.id)+'">Learn with this record</button><button type="button" class="primary" data-action="enrich" data-id="'+esc(S.record.id)+'">Fetch publisher details</button>'+(S.user?'<button type="button" data-action="watch-cve" data-id="'+esc(S.record.id)+'">Watch this CVE</button><button type="button" data-action="highlight-add" data-id="'+esc(S.record.id)+'">Add to highlights</button>':'')+'</div>';
    await renderRecordTab();
  }catch(error){
    if($('#dialog').open&&epoch===S.dialogEpoch)$('#dialog-content').innerHTML=empty('The record could not be opened',message(error),'<button type="button" class="primary" data-record="'+esc(identifier)+'">Try again</button>');
    throw error;
  }
}
async function renderRecordTab(){
  const r=S.record,tab=S.recordTab,container=$('#record-tab-content'),epoch=S.dialogEpoch;
  if(!r||!container)return;
  S.graph?.dispose();S.graph=null;S.graphModel=null;
  $$('#dialog [data-action="record-tab"]').forEach(el=>el.setAttribute('aria-pressed',String(el.dataset.tab===tab)));
  if(tab==='overview')container.innerHTML=overviewMarkup(r)+'<details class="panel"><summary>How the triage priority is calculated</summary>'+priorities(r.priority)+'</details>';
  else if(tab==='evidence')container.innerHTML=evidenceMarkup(r);
  else if(tab==='packages')container.innerHTML='<h3>Affected software & published fixes</h3>'+packageEvidence(r.packages)+(S.recordStatements.length?'<h3 class="spaced">Vendor applicability statements</h3>'+statementsHTML(S.recordStatements):'');
  else if(tab==='graph'){
    container.innerHTML='<h3>Follow this CVE’s evidence</h3><p>Each connection is supported by a source observation, an affected-product statement, or a publisher reference.</p><div id="graph-container"></div>';
    await openEvidenceGraph();
  }else if(tab==='patterns'){
    container.innerHTML='<p class="loading">Reading MITRE’s published weakness relationships…</p>';
    try{const data=await api('/api/taxonomy?id='+encodeURIComponent(r.id));if(epoch===S.dialogEpoch&&S.recordTab===tab)container.innerHTML=taxonomyMarkup(data);}
    catch(error){if(epoch===S.dialogEpoch&&S.recordTab===tab){
      const cwes=(r.cwes||[]).filter(id=>/^CWE-\d+$/.test(id));
      container.innerHTML=empty('Mapping unavailable',message(error),'<button type="button" data-action="record-tab" data-tab="patterns">Retry published mappings</button>')+
        (cwes.length?'<h3>Weaknesses reported by this record’s sources</h3><div class="button-row">'+cwes.map(id=>link('https://cwe.mitre.org/data/definitions/'+id.slice(4)+'.html',id)).join('')+'</div>':'')+
        '<p class="spaced">'+link('https://capec.mitre.org/data/downloads.html','Open MITRE’s published CAPEC catalog')+'</p>';
    }}
  }else if(tab==='ai')container.innerHTML=aiIntro(S.ai,S.user);
  else if(tab==='history'){
    container.innerHTML='<p class="loading">Reading saved observations…</p>';
    const data=await api('/api/events?id='+encodeURIComponent(r.id));
    if(epoch!==S.dialogEpoch||S.recordTab!==tab||S.record?.id!==r.id)return;
    container.innerHTML='<p class="muted">Collection began '+date(data.baseline)+'. These are changes saved by this instance.</p>'+(data.events.length?data.events.map(eventMarkup).join(''):empty('No changes saved for this record yet','Its first import established the baseline. Later source changes appear here.'));
  }
  hydrateIcons(container);
}
async function showFinding(identifier){
  openDialog('Finding evidence','<p class="loading">Connecting the evidence…</p>');const epoch=S.dialogEpoch=(S.dialogEpoch||0)+1;
  const data=await api('/api/evidence?id='+encodeURIComponent(identifier));if(!$('#dialog').open||epoch!==S.dialogEpoch)return;
  const f=data.finding,c=data.component,r=data.record;S.evidence=data;S.record=null;
  $('#dialog-title').textContent=c.name+'@'+c.version;
  let html='<span class="kicker">'+esc(data.inventory)+' · '+esc(c.ecosystem)+'</span><h3 class="record-heading">'+esc(f.title)+'</h3><div class="button-row">'+severityPill(r&&r.severity!=='Unknown'?r:f)+(r?.kev||f.kev?pill('CISA KEV','coral'):'')+'<span class="record-id">'+esc(f.advisoryId)+'</span></div>'+
    '<div class="evidence-map"><div class="evidence-node"><small>Installed package</small><strong>'+esc(c.name)+'@'+esc(c.version)+'</strong><p class="subcell">'+esc(c.evidence)+'</p></div><span class="evidence-arrow">→</span><div class="evidence-node"><small>OSV version match</small><strong>'+esc(f.advisoryId)+'</strong>'+link(f.url,'Matching advisory')+'</div><span class="evidence-arrow">→</span><div class="evidence-node"><small>Publisher-reported fixes</small><strong>'+esc(f.fixedVersions.length?f.fixedVersions.join(', '):'No fixed version supplied')+'</strong></div></div>'+
    '<div class="split"><h3>Explore this evidence in 3D</h3>'+button('Open 3D evidence graph','evidence-3d','primary')+'</div><div id="graph-container" hidden></div>'+
    '<p class="record-description spaced">'+esc(f.description)+'</p><div class="split-panels"><section>'+priorities(f.priority)+'</section><section><h3>Published remediation</h3>'+
    (f.fixedVersions.length?'<p>Fixed releases reported for this package: <strong class="mono">'+esc(f.fixedVersions.join(', '))+'</strong>.</p><p class="muted">Use the affected range to identify the compatible release for your branch.</p>':'<p class="muted">The advisory does not supply a fixed version.</p>')+
    link(f.url,'Open the publisher’s advisory')+(r?.requiredAction?'<p class="spaced">'+esc(r.requiredAction)+'</p>':'')+'</section></div>'+
    '<details class="panel"><summary>Affected ranges and dependency paths</summary><pre>'+esc(JSON.stringify(f.affectedRanges,null,2))+'</pre>'+
    '<p class="muted">'+esc((c.locations||[]).join(', ')||'No dependency path supplied.')+'</p>'+
    (data.dependencies.length?'<ul>'+data.dependencies.map(e=>'<li><code>'+esc(e.from)+'</code> → <code>'+esc(e.to)+'</code></li>').join('')+'</ul>':'')+'</details>'+
    '<details class="panel"><summary>Vendor applicability statements</summary>'+statementsHTML(data.statements)+'</details>'+
    '<form id="remediation-form" class="panel"><h3>Track the next action</h3><input type="hidden" name="id" value="'+f.id+'"><div class="form-grid"><label>Status<select name="status">'+['open','acknowledged','mitigating','resolved'].map(v=>opt(v,v.replaceAll('_',' '),f.status)).join('')+'</select></label><label class="span-all">Remediation note<textarea name="note" maxlength="2000">'+esc(f.note)+'</textarea></label></div><p class="form-error" role="alert"></p><button class="primary spaced" type="submit">Save status</button></form>'+
    '<h3>Source observations</h3>'+sourceList(r)+'<ul class="reference-list"><li>'+link(f.url,'OSV exact package/version match')+'<span class="subcell">Observed '+date(f.observedAt,true)+'</span></li></ul>';
  $('#dialog-content').innerHTML=html;
}
function graphModel(data){
  const f=data.finding,c=data.component,r=data.record,nodes=[],edges=[];
  const add=(id,label,kind,column,source,detail)=>{if(!nodes.some(n=>n.id===id))nodes.push({id,label,kind,column,source,detail});return id;};
  const connect=(from,to,label,source)=>edges.push({from,to,label,source});
  const component=add('package',c.name+'@'+c.version,'package',0,'','Installed component from '+data.inventory+'. '+(c.locations||[]).join(', '));
  const advisory=add('advisory',f.advisoryId,'advisory',1,f.url,f.title);
  connect(component,advisory,'OSV exact package/version match',f.url);
  const cves=f.aliases.filter(a=>/^CVE-\d{4}-\d{4,}$/.test(a)).slice(0,12);
  for(const id of cves){add(id,id,'vulnerability',2,f.url,'CVE alias reported in the OSV advisory.');connect(advisory,id,'Advisory identifies CVE',f.url);}
  if(r?.kev){const url=r.sources.find(s=>s.id==='cisa')?.url||'';add('kev','CISA KEV','exploitation',3,url,r.requiredAction||'This CVE is in the collected CISA KEV catalog.');connect(nodes.some(n=>n.id===r.id)?r.id:advisory,'kev','Listed as known exploited',url);}
  f.fixedVersions.slice(0,12).forEach((version,index)=>{const id=add('fix-'+index,version,'fix',3,f.url,'Publisher-reported fixed version for '+c.name+'. Check the advisory’s affected range for branch applicability.');connect(advisory,id,'Published fixed release',f.url);});
  data.statements.slice(0,8).forEach((s,index)=>{const id=add('statement-'+index,s.status.replaceAll('_',' '),'statement',4,s.document?.url||'',(s.document?.issuer||s.sourceName||'Publisher')+': '+(s.justification||s.impact||'')+(s.contextPurl?' | Context: '+s.contextPurl:''));connect(component,id,s.contextPurl&&!s.contextMatches?'Statement for a different product context':'Publisher applicability statement',s.document?.url||'');});
  return {nodes,edges};
}
async function openEvidenceGraph(){
  if(!S.evidence&&!S.record)return;
  S.graph?.dispose();S.graph=null;
  const container=$('#graph-container');container.hidden=false;
  const model=S.evidence?graphModel(S.evidence):recordGraphModel(S.record);S.graphModel=model;
  container.innerHTML='<p class="muted"><small>Drag one finger to orbit, pinch to zoom, or use the camera buttons. Select a label to follow its evidence.</small></p><div class="evidence-graph-stage"><canvas id="evidence-canvas" tabindex="0" aria-label="3D evidence graph. Arrow keys orbit, plus and minus zoom, Home resets."></canvas><div id="evidence-labels"></div><div class="graph-camera-controls">'+[['left','←'],['right','→'],['up','↑'],['down','↓'],['in','+'],['out','−'],['reset','Fit view']].map(([direction,label])=>'<button type="button" data-action="graph-camera" data-direction="'+direction+'" aria-label="Camera '+direction+'">'+label+'</button>').join('')+'</div></div><div class="graph-toolbar">'+model.nodes.map((n,i)=>'<button type="button" class="small" data-action="graph-node" data-index="'+i+'">'+esc(n.label)+'</button>').join('')+'</div><div id="graph-details" class="notice"></div>';
  if(model.limited)container.insertAdjacentHTML('afterbegin','<p class="muted">The graph shows up to 16 products and 14 tagged references. All supplied details are available in the other investigation sections.</p>');
  selectGraphNode(model.nodes[0]);
  const canvas=$('#evidence-canvas'),labels=$('#evidence-labels'),epoch=S.dialogEpoch;
  try{
    const {EvidenceGraph}=await import('./evidence-graph.js');
    if(!$('#dialog').open||epoch!==S.dialogEpoch||$('#evidence-canvas')!==canvas)return;
    S.graph=new EvidenceGraph(canvas,labels,model,node=>selectGraphNode(node),()=>toast('The 3D view is unavailable. The evidence buttons remain usable.'));
  }catch{toast('WebGL could not start. Use the evidence buttons to inspect every connection.');}
}
function selectGraphNode(node){
  if(!node||!$('#graph-details'))return;
  const edges=S.graphModel.edges.filter(e=>e.from===node.id||e.to===node.id);
  $('#graph-details').innerHTML='<strong>'+esc(node.label)+'</strong><p>'+esc(node.detail)+'</p>'+edges.map(e=>'<p>'+esc(S.graphModel.nodes.find(n=>n.id===e.from)?.label)+' → '+esc(S.graphModel.nodes.find(n=>n.id===e.to)?.label)+' · '+esc(e.label)+(e.source?' · '+link(e.source,'Source'):'')+'</p>').join('')+(node.source?link(node.source,'Open source'):'');
}
function importForm(replace=false){
  openDialog(replace?'Replace inventory manifest':'Import your software','<form id="import-form" class="stack"><input type="hidden" name="replace" value="'+(replace?esc(S.inventory):'')+'">'+
    (!replace?'<label>Inventory name<input name="name" required maxlength="100" autocomplete="off"></label>':'<p>Upload the current manifest for <strong>'+esc(S.inventoryDetail?.inventory.name)+'</strong>. Existing findings retain their history; removed components are recorded as removed.</p>')+
    '<label>Manifest or SBOM<input type="file" name="file" required accept=".json,.txt,.lock,.sum,.mod,.xml"><small>npm lockfile, requirements.txt, Poetry, Cargo, Go, Maven POM, CycloneDX JSON, or SPDX JSON. Up to 5 MiB / 5,000 components.</small></label>'+
    (!replace?'<div class="form-grid"><label>Asset importance<select name="criticality">'+[1,2,3,4,5].map(n=>opt(n,n+' / 5',3)).join('')+'</select></label><label class="check"><input type="checkbox" name="exposed">Internet-facing software</label></div>':'')+
    '<p class="muted">Package names and exact versions are sent to OSV for matching. The supplied file stays in your private inventory; it is never executed.</p><p class="form-error" role="alert"></p><button type="submit" class="primary">'+(replace?'Update inventory & check':'Import & check')+'</button></form>');
}
function watchForm(scope='vendor',selector=''){
  openDialog('Create a watch','<form id="watch-form" class="stack"><label>Watch name<input name="name" required maxlength="100"></label><div class="form-grid"><label>Follow<select name="scope">'+['vendor','product','cve','package','inventory'].map(v=>opt(v,v==='cve'?'CVE / advisory':v,scope)).join('')+'</select></label><label id="watch-inventory-field">Inventory<select name="inventory">'+opt('','All my inventories',selector)+S.inventories.map(i=>opt(i.id,i.name,selector)).join('')+'</select></label><label id="watch-selector-field">Name or identifier<input name="selector" maxlength="200" value="'+esc(scope==='inventory'?'':selector)+'"></label><label>Notify when<select name="trigger">'+opt('either','Known exploited or priority threshold','either')+opt('kev','Known exploited','either')+opt('priority','Priority crosses threshold','either')+'</select></label><label>Priority threshold<input name="threshold" type="number" min="0" max="100" value="70" required></label><label>Delivery<select name="channel"><option value="inapp">Inbox & Atom feed</option><option value="webhook">Webhook</option><option value="email">Email</option></select></label><label id="watch-target-field" hidden>Destination<input name="target" autocomplete="off" maxlength="3000"><small>HTTPS webhook URL or recipient address. Email requires configured SMTP settings.</small></label></div><p class="muted">This watch establishes today’s baseline. Later matching changes create notifications.</p><p class="form-error" role="alert"></p><button type="submit" class="primary">Create watch</button></form>');
  updateWatchFields();
}
function updateWatchFields(){
  const form=$('#watch-form');if(!form)return;
  const inventory=form.elements.scope.value==='inventory';
  $('#watch-inventory-field').hidden=!inventory;$('#watch-selector-field').hidden=inventory;
  form.elements.selector.required=!inventory;
  const target=form.elements.channel.value!=='inapp';$('#watch-target-field').hidden=!target;form.elements.target.required=target;
}
function vendorForm(){
  openDialog('Connect vendor evidence','<form id="vendor-form" class="stack"><label>Publisher or source name<input name="name" required maxlength="100"></label><label>Input<select name="mode"><option value="url">HTTPS document or CSAF provider metadata</option><option value="file">Upload CSAF / OpenVEX JSON</option></select></label><label id="vendor-url-field">Source URL<input type="url" name="url" required autocomplete="off"><small>Public HTTPS on port 443. Redirects and private network addresses are blocked.</small></label><label id="vendor-file-field" hidden>Publisher document<input type="file" name="file" accept=".json"></label><label class="check"><input type="checkbox" name="trusted">I have verified this publisher’s identity</label><p class="muted">Applicability statements retain their publisher and product context. They appear alongside vulnerability evidence.</p><p class="form-error" role="alert"></p><button type="submit" class="primary">Add source</button></form>');
}
function help(){
  openDialog('How to read this intelligence','<div class="help-grid"><section><h3>Where the records come from</h3><p>CISA KEV, NVD, GitHub Advisories, FIRST EPSS, CVE/CNA, and OSV supply the catalog and its evidence. Source links and observation dates appear inside every investigation. The catalog starts empty and fills from providers.</p></section><section><h3>What the scores answer</h3><p>CVSS describes technical severity. EPSS estimates the probability of exploitation over the next 30 days. KEV identifies vulnerabilities CISA lists as exploited in the wild. MasterMonk’s priority points are a visible calculation for triage.</p></section><section><h3>Reading the evidence cosmos</h3><p>Core color shows severity, size uses CVSS, and the corona uses EPSS when available. A red orbit marks CISA KEV. Selecting a CVE reveals satellites for its collected source providers; vendor-system lines are shared-vendor relationships, not attack paths.</p></section><section><h3>Learning with a record</h3><p>The Investigation Lab keeps the selected CVE, its source evidence, technical conditions, exploitation signals, and response guidance in one workspace. It records learning checks only in the current browser session and never creates vulnerability facts.</p></section></div><div class="dialog-footer">'+button('Open the Investigation Lab','learn-home','primary')+'</div>');
}
function packageForm(){
  openDialog('Check an exact package version','<form id="package-form" class="stack"><div class="form-grid"><label>Ecosystem<select name="ecosystem">'+['npm','PyPI','Maven','Go','crates.io','NuGet','Packagist','RubyGems'].map(v=>opt(v,v,'npm')).join('')+'</select></label><label>Package name<input name="name" required maxlength="200"></label><label>Installed version<input name="version" required maxlength="100"></label></div><p class="form-error" role="alert"></p><button type="submit" class="primary">Query OSV</button></form><div id="package-results" class="spaced"></div>');
}
async function dispatch(action,el){
  if(action==='help')return help();
  if(action==='install-app'){
    if(S.installPrompt){
      const prompt=S.installPrompt;S.installPrompt=null;await prompt.prompt();await prompt.userChoice;updateInstallButton();return;
    }
    const ios=/iPad|iPhone|iPod/.test(navigator.userAgent)||(navigator.platform==='MacIntel'&&navigator.maxTouchPoints>1);
    return openDialog('Install MasterMonk',ios?'<p>In Safari, tap <strong>Share</strong>, then choose <strong>Add to Home Screen</strong>.</p><p class="muted">The installed app connects to this same MasterMonk server for current public-source intelligence.</p>':'<p>Use your browser menu and choose <strong>Install app</strong> or <strong>Add to Home screen</strong>.</p><p class="muted">Installation is available on HTTPS deployments and on localhost.</p>');
  }
  if(action==='learn-home')return navigate('learn');
  if(action==='close-dialog')return $('#dialog').close();
  if(action==='account')return S.user?navigate('settings'):showAuth();
  if(action==='browse-public')return navigate('discover');
  if(action==='tools')return openDialog('Optional tools & administration','<p>The public intelligence catalog and learning views are available directly. Accounts add saved watches, private package checks, and instance administration.</p><div class="button-row">'+button(S.user?'Open settings':'Administration sign-in','account','primary')+'<a class="button-link" href="#watchlists" data-close-navigation>Saved watches</a><a class="button-link" href="#workspace" data-close-navigation>Private package tools</a></div>');
  if(action==='open-record')return showRecord(el.dataset.id);
  if(action==='record-tab'){S.recordTab=el.dataset.tab;return renderRecordTab();}
  if(action==='learn-record'){
    const id=el.dataset.id,record=S.record?.id===id?S.record:(await api('/api/record?id='+encodeURIComponent(id))).record;
    S.learnRecord=record;S.learnStep=0;S.learnFocus=0;S.learnChecks=[];$('#dialog').close();return navigate('learn');
  }
  if(action==='learn-step'){S.learnStep=Math.max(0,Math.min(3,Number(el.dataset.step)));S.learnFocus=0;if(S.learnRecord)put(learningMarkup(S.learnRecord,S.learnStep,{focus:0,checks:S.learnChecks}),S.epoch);return;}
  if(action==='learn-focus'){S.learnFocus=Math.max(0,Number(el.dataset.focus)||0);if(S.learnRecord)put(learningMarkup(S.learnRecord,S.learnStep,{focus:S.learnFocus,checks:S.learnChecks}),S.epoch);return;}
  if(action==='learn-check'){const key=el.dataset.check,checks=new Set(S.learnChecks);if(checks.has(key))checks.delete(key);else checks.add(key);S.learnChecks=[...checks];if(S.learnRecord)put(learningMarkup(S.learnRecord,S.learnStep,{focus:S.learnFocus,checks:S.learnChecks}),S.epoch);return;}
  if(action==='learn-copy'){
    const text=learningBrief(S.learnRecord);try{await navigator.clipboard.writeText(text);toast('Investigation brief copied.');}
    catch{return openDialog('Investigation brief','<p>Copy the sourced brief below.</p><pre>'+esc(text)+'</pre>');}return;
  }
  if(action==='learn-choose'){S.catalog={q:'',severity:'all',kev:false,days:'0',sort:'newest',offset:0};toast('Open any record, then choose Learn with this record.');return navigate('catalog');}
  if(action==='latest-catalog'){S.catalog={q:'',severity:'all',kev:false,days:'0',sort:'newest',offset:0};return navigate('catalog');}
  if(action==='clear-filters'){S.catalog={q:'',severity:'all',kev:false,days:'0',sort:'newest',offset:0};return loadCatalog(S.epoch);}
  if(action==='settings')return navigate('settings');
  if(action==='sources')return navigate('sources');
  if(action==='refresh')return refreshView();
  if(action==='import')return importForm();
  if(action==='replace')return importForm(true);
  if(action==='inventory-settings')return inventorySettings();
  if(action==='components')return componentDialog();
  if(action==='component-page')return componentDialog(Number(el.dataset.offset));
  if(action==='package')return packageForm();
  if(action==='watch')return watchForm();
  if(action==='watch-inventory')return watchForm('inventory',el.dataset.id);
  if(action==='watch-cve')return watchForm('cve',el.dataset.id);
  if(action==='vendor')return vendorForm();
  if(action==='evidence-3d')return openEvidenceGraph();
  if(action==='trend-period')return openTrendPeriod(el);
  if(action==='graph-camera')return S.graph?.orbit(el.dataset.direction);
  if(action.startsWith('universe-orbit-'))return S.universe?.orbit(action.slice('universe-orbit-'.length));
  if(action==='universe-center-selected')return S.universe?.orbit('center');
  if(action==='highlight-add'){
    if(!S.user)throw new Error('Sign in to create a highlights page.');
    const draft=S.highlightDraft;if(draft.items.some(r=>r.id===el.dataset.id)){toast('This record is already in your highlights draft.');return;}
    if(draft.items.length>=24)throw new Error('A highlights page can contain up to 24 records.');
    const record=S.record?.id===el.dataset.id?S.record:S.universeRecords.find(r=>r.id===el.dataset.id)||(await api('/api/record?id='+encodeURIComponent(el.dataset.id))).record;
    draft.items.push({id:record.id,title:record.title,note:''});toast('Added to highlights. Open Highlights in navigation to write and share your briefing.');return;
  }
  if(action==='highlight-remove'){rememberHighlightDraft();S.highlightDraft.items=S.highlightDraft.items.filter(r=>r.id!==el.dataset.id);return loadHighlights(S.epoch);}
  if(action==='highlights-manage'){
    S.sharedToken='';const url=new URL(location.href);url.searchParams.delete('highlight');history.replaceState(null,'',url);return navigate('highlights');
  }
  if(action==='highlight-open'){S.sharedToken=el.dataset.token;history.replaceState(null,'',highlightURL(S.sharedToken));return navigate('highlights');}
  if(action==='highlight-copy'){
    const url=highlightURL(el.dataset.token);
    try{await navigator.clipboard.writeText(url);toast('Link copied. The server must remain reachable.');}
    catch{openDialog('Highlights link','<p>Copy the link below. It works while this instance is reachable.</p><input aria-label="Highlights link" readonly value="'+esc(url)+'">');}return;
  }
  if(action==='component-badge-copy'){
    const target=document.getElementById(el.dataset.target),text=target?.value||'';
    if(!text)throw new Error('The badge code is unavailable.');
    try{await navigator.clipboard.writeText(text);toast('Badge code copied.');}
    catch{return openDialog('Embeddable badge code','<p>Copy the code below.</p><textarea readonly rows="4">'+esc(text)+'</textarea>');}return;
  }
  if(action==='highlight-state'){
    if(el.dataset.mode==='delete'&&!confirm('Delete this highlights page and its notes? The source vulnerability records will remain.'))return;
    await api('/api/highlights/action',{id:el.dataset.id,action:el.dataset.mode});return loadHighlights(S.epoch);
  }
  if(action==='ai-generate'){
    const record=S.record,epoch=S.dialogEpoch;if(!record)return;
    const container=$('#record-tab-content');container.innerHTML='<p class="loading">Waiting for the configured model. Original evidence remains unchanged…</p>';
    try{const result=await api('/api/ai/explain',{id:record.id});if(epoch===S.dialogEpoch&&S.recordTab==='ai')container.innerHTML=aiMarkup(result);}
    catch(error){if(epoch===S.dialogEpoch&&S.recordTab==='ai')container.innerHTML=aiIntro(S.ai,S.user)+'<p class="notice error">'+esc(message(error))+'</p>';}
    return;
  }
  if(action==='graph-node'){const node=S.graphModel.nodes[Number(el.dataset.index)];S.graph?.focus(node.id);return selectGraphNode(node);}
  if(action==='universe-pause'){const paused=S.universe?.toggle();$('#motion-button').textContent=paused?'Resume motion':'Pause motion';return;}
  if(action==='universe-reset')return S.universe?.reset();
  if(action==='universe-controls-toggle')return setUniverseControls(!$('#universe-control-panel').classList.contains('is-open'));
  if(action==='universe-controls-close')return setUniverseControls(false);
  if(action==='universe-selection-close')return closeUniverseSelection();
  if(action==='universe-fullscreen')return toggleUniverseFullscreen();
  if(action==='universe-zoom-in')return S.universe?.setZoom(S.universe.zoom*1.2);
  if(action==='universe-zoom-out')return S.universe?.setZoom(S.universe.zoom/1.2);
  if(action==='catalog-page'){S.catalog.offset=Number(el.dataset.offset);return loadCatalog(S.epoch);}
  if(action==='findings-page'){S.findingOffset=Number(el.dataset.offset);return loadWorkspace(S.epoch);}
  if(action==='inbox-page'){S.inboxOffset=Number(el.dataset.offset);return loadWatches(S.epoch);}
  if(action==='scan'){await api('/api/inventories/action',{id:el.dataset.id,action:'scan'});toast('Inventory check queued.');return loadWorkspace(S.epoch);}
  if(action==='inventory-pause'){await api('/api/inventories/action',{id:el.dataset.id,action:el.dataset.mode});return loadWorkspace(S.epoch);}
  if(action==='delete-inventory'){
    if(!confirm('Delete this inventory and its stored components and findings?'))return;
    await api('/api/inventories/action',{id:el.dataset.id,action:'delete'});S.inventory='';S.findingOffset=0;$('#dialog').close();toast('Inventory deleted.');return loadWorkspace(S.epoch);
  }
  if(action==='sync'){const result=await api('/api/sync',{});toast(result.message);return loadSources(S.epoch);}
  if(action==='backfill'){
    if(el.dataset.mode==='restart'&&!confirm('Start a new historical import pass? Existing records will be preserved.'))return;
    await api('/api/backfill',{action:el.dataset.mode});toast('Historical import updated.');return loadSources(S.epoch);
  }
  if(action==='watch-toggle'||action==='watch-delete'){
    if(action==='watch-delete'&&!confirm('Delete this watch? Existing inbox entries remain available.'))return;
    await api('/api/watch-rules/action',{id:el.dataset.id,action:action==='watch-delete'?'delete':el.dataset.mode});return loadWatches(S.epoch);
  }
  if(action==='read-alerts'){await api('/api/alerts/read',{});return loadWatches(S.epoch);}
  if(action==='feed'){openDialog('Private Atom feed','<p>Create a private link for your feed reader. Anyone with the link can read your watch notifications. Creating a new link replaces the previous one.</p>'+button('Create or rotate link','create-feed','primary'));return;}
  if(action==='create-feed'){const data=await api('/api/alerts/feed',{});return openDialog('Your Atom feed link','<p>Copy this link into your feed reader. It is shown once.</p><p class="secret-box">'+esc(location.origin+data.path)+'</p>');}
  if(['vendor-refresh','vendor-toggle','vendor-delete'].includes(action)){
    if(action==='vendor-delete'&&!confirm('Remove this vendor source and its saved statements?'))return;
    await api('/api/vendor-sources/action',{id:el.dataset.id,action:action==='vendor-refresh'?'refresh':action==='vendor-delete'?'delete':el.dataset.mode});return loadSources(S.epoch);
  }
  if(action==='vendor-statements'){const data=await api('/api/vendor-sources?source='+encodeURIComponent(el.dataset.id));return openDialog('Publisher statements',statementsHTML(data.statements)+(data.statements.length===500?'<p class="muted">Showing the latest 500 statements. Individual finding views select statements for the matching package and vulnerability.</p>':''));}
  if(action==='enrich'){
    const id=el.dataset.id,epoch=S.dialogEpoch,previous=el.textContent;el.textContent='Fetching publisher details…';
    try{const data=await api('/api/lookup',{id});if($('#dialog').open&&S.dialogEpoch===epoch)return showRecord(data.record.id);}
    finally{if(el.isConnected)el.textContent=previous;}
    return;
  }
  if(action==='older-events'){
    const last=S.events.at(-1);if(!last)return;
    const data=await api('/api/events?before='+last.id);
    if(!data.events.length){toast('You have reached the start of saved history.');el.disabled=true;return;}
    S.events.push(...data.events);return renderChanges(S.epoch);
  }
  if(action==='save-filter'){return openDialog('Save current search','<form id="filter-form" class="stack"><label>Filter name<input name="name" required maxlength="60"></label><p class="form-error" role="alert"></p><button type="submit" class="primary">Save filter</button></form>');}
  if(action==='delete-filter'){const filters=S.profile.filters.filter((_,i)=>i!==Number(el.dataset.index));S.profile=await api('/api/profile',{filters});return loadSettings(S.epoch);}
  if(action==='token'){return openDialog('Create an API token','<form id="token-form" class="stack"><label>Token name<input name="name" required maxlength="60"></label><label class="check"><input type="checkbox" checked disabled>Read your workspace</label><label class="check"><input type="checkbox" name="scan" checked>Run package checks and inventory scans</label><label class="check"><input type="checkbox" name="write">Import, update, or delete your inventories</label><p class="muted">Expires after 90 days. Administrator and account-management actions require an interactive session.</p><p class="form-error" role="alert"></p><button type="submit" class="primary">Create token</button></form>');}
  if(action==='revoke-token'){if(!confirm('Revoke this API token?'))return;await api('/api/tokens/revoke',{digest:el.dataset.digest});return loadSettings(S.epoch);}
  if(action==='password'){return openDialog('Change password','<form id="password-form" class="stack"><label>Current password<input type="password" name="current" required autocomplete="current-password"></label><label>New password<input type="password" name="password" required minlength="15" maxlength="128" autocomplete="new-password"></label><p class="muted">Changing your password signs out existing sessions and revokes API tokens.</p><p class="form-error" role="alert"></p><button type="submit" class="primary">Change password</button></form>');}
  if(action==='add-user'){return openDialog('Add a team member','<form id="user-form" class="stack"><label>Username<input name="username" required minlength="3" maxlength="40" autocomplete="off"></label><label>Initial password<input type="password" name="password" required minlength="15" maxlength="128" autocomplete="new-password"></label><label>Role<select name="role"><option value="member">Member</option><option value="admin">Administrator</option></select></label><p class="form-error" role="alert"></p><button type="submit" class="primary">Create account</button></form>');}
  if(action==='disable-user'){if(!confirm('Disable access for '+el.dataset.name+'? Sessions and API tokens will be revoked.'))return;await api('/api/users/disable',{id:Number(el.dataset.id)});return loadSettings(S.epoch);}
  if(action==='logout'){await api('/api/auth/logout',{});S.user=null;S.profile={weights:{},filters:[]};S.inventories=[];S.findings=[];S.highlightDraft={title:'',note:'',items:[]};showAuth();if(S.public)navigate('discover');}
}
async function submit(form){
  const f=form.elements,data=Object.fromEntries(new FormData(form));
  if(form.id==='auth-form'){
    const result=await api(S.setup?'/api/auth/setup':'/api/auth/login',data);S.user=result.user;S.setup=false;form.reset();
    S.profile=await api('/api/profile');$('#auth-error').textContent='';return navigate('settings');
  }
  if(form.id==='lookup-form'){
    const raw=data.id.trim(),id=/^cve-/i.test(raw)?raw.toUpperCase():/^ghsa-/i.test(raw)?'GHSA-'+raw.slice(5).toLowerCase():raw;
    if(!/^(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$/.test(id))throw new Error('Enter a complete CVE or GHSA identifier.');
    const epoch=S.epoch;let record;
    try{record=(await api('/api/record?id='+encodeURIComponent(id))).record;}
    catch(error){if(error.status!==404)throw error;record=(await api('/api/lookup',{id})).record;}
    if(epoch===S.epoch)return showRecord(record.id);return;
  }
  if(form.id==='workspace-filters'){S.inventory=data.inventory;S.resolved=!!data.resolved;S.findingOffset=0;return loadWorkspace(S.epoch);}
  if(form.id==='catalog-filters'){S.catalog={q:data.q,severity:data.severity,kev:!!data.kev,days:data.days,sort:data.sort,offset:0};return loadCatalog(S.epoch);}
  if(form.id==='trend-filters'){S.trendDays=Number(data.days);S.trendBasis=data.basis;return loadChanges(S.epoch);}
  if(form.id==='comparison-form'){
    const epoch=S.epoch;S.comparison={from:data.from,to:data.to,result:null};
    $('#comparison-results').innerHTML='<p class="loading">Comparing saved observations…</p>';
    try{const result=await api('/api/compare?'+new URLSearchParams({from:data.from,to:data.to}));S.comparison.result=result;if(epoch===S.epoch&&S.view==='changes')$('#comparison-results').innerHTML=comparisonMarkup(result);}
    catch(error){if(epoch===S.epoch&&$('#comparison-results'))$('#comparison-results').innerHTML='<p class="notice error">'+esc(message(error))+'</p>';throw error;}return;
  }
  if(form.id==='component-compare-form'){
    const left={ecosystem:data.left_ecosystem,name:data.left_name.trim(),version:data.left_version.trim()};
    const right={ecosystem:data.right_ecosystem,name:data.right_name.trim(),version:data.right_version.trim()};
    const epoch=S.epoch;S.componentComparison={left,right,result:null};
    $('#component-results').innerHTML='<p class="loading">Querying current OSV exact-version evidence…</p>';
    try{
      const result=await api('/api/component-compare?'+new URLSearchParams({
        left_ecosystem:left.ecosystem,left_name:left.name,left_version:left.version,
        right_ecosystem:right.ecosystem,right_name:right.name,right_version:right.version
      }));
      S.componentComparison={left:result.left.component,right:result.right.component,result};
      if(epoch===S.epoch&&S.view==='components')$('#component-results').innerHTML=componentComparisonMarkup(result,location.origin);
    }catch(error){if(epoch===S.epoch&&$('#component-results'))$('#component-results').innerHTML='<p class="notice error">'+esc(message(error))+'</p>';throw error;}return;
  }
  if(form.id==='highlight-form'){
    rememberHighlightDraft();const draft=S.highlightDraft;
    const result=await api('/api/highlights',{title:draft.title,note:draft.note,items:draft.items.map(({id,note})=>({id,note}))});
    S.highlightDraft={title:'',note:'',items:[]};S.sharedToken=result.token;history.replaceState(null,'',highlightURL(result.token));
    toast('Highlights created. You can revoke the link from Manage my highlights.');return loadHighlights(S.epoch);
  }
  if(form.id==='universe-filters'){await loadUniverse(S.epoch);setUniverseControls(false);return;}
  if(form.id==='import-form'){
    const file=f.file.files[0];if(!file||file.size>5*1024*1024)throw new Error('Choose a manifest or SBOM of at most 5 MiB.');
    const payload={filename:file.name,content:await file.text()};
    const result=data.replace?await api('/api/inventories/replace',{...payload,id:data.replace}):await api('/api/inventories',{...payload,name:data.name,criticality:Number(data.criticality),exposed:f.exposed.checked});
    S.inventory=result.inventory.id;S.findingOffset=0;$('#dialog').close();toast('Inventory imported. Package check queued.');return navigate('workspace');
  }
  if(form.id==='inventory-settings-form'){await api('/api/inventories/action',{id:data.id,action:'settings',criticality:Number(data.criticality),exposed:f.exposed.checked,auto_refresh:f.auto_refresh.checked});$('#dialog').close();return loadWorkspace(S.epoch);}
  if(form.id==='remediation-form'){await api('/api/findings/status',data);toast('Remediation status saved.');return;}
  if(form.id==='watch-form'){await api('/api/watch-rules',{name:data.name,scope:data.scope,selector:data.scope==='inventory'?data.inventory:data.selector,trigger:data.trigger,threshold:Number(data.threshold),channel:data.channel,target:data.target});$('#dialog').close();toast('Watch created from the current evidence.');return navigate('watchlists');}
  if(form.id==='vendor-form'){
    const payload={name:data.name,trusted:f.trusted.checked};
    if(data.mode==='file'){const file=f.file.files[0];if(!file||file.size>5*1024*1024)throw new Error('Choose a JSON document of at most 5 MiB.');payload.document=JSON.parse(await file.text());}
    else payload.url=data.url;
    await api('/api/vendor-sources',payload);$('#dialog').close();toast('Vendor evidence source added.');return loadSources(S.epoch);
  }
  if(form.id==='package-form'){const result=await api('/api/package',data);$('#package-results').innerHTML='<p>'+esc(result.partial?'The response has further pages; this result is incomplete.':result.records.length+' matching vulnerability records returned.')+'</p>'+recordTable(result.records);return;}
  if(form.id==='weights-form'){S.profile=await api('/api/profile',{weights:Object.fromEntries(Object.entries(data).map(([k,v])=>[k,Number(v)]))});toast('Priority weights saved. Findings will use your profile.');return;}
  if(form.id==='filter-form'){S.profile=await api('/api/profile',{filters:[...S.profile.filters.filter(x=>x.name!==data.name),{name:data.name,...S.catalog}]});$('#dialog').close();toast('Search saved.');return loadCatalog(S.epoch);}
  if(form.id==='token-form'){const scopes=['read'];if(f.scan.checked)scopes.push('scan');if(f.write.checked)scopes.push('inventory:write');const result=await api('/api/tokens',{name:data.name,scopes});openDialog('Save your API token','<p>Store this token in your CI secret store. It will not be shown again.</p><p class="secret-box">'+esc(result.token)+'</p>');return;}
  if(form.id==='password-form'){await api('/api/auth/password',data);$('#dialog').close();S.user=null;showAuth();toast('Password changed. Sign in again.');return;}
  if(form.id==='user-form'){await api('/api/users',data);form.reset();$('#dialog').close();toast('Account created.');return loadSettings(S.epoch);}
}
document.addEventListener('click',async event=>{
  if(event.target.closest('[data-close-navigation]'))$('#dialog').close();
  const el=event.target.closest('button');if(!el||el.disabled)return;
  const action=el.dataset.action,record=el.dataset.record,finding=el.dataset.finding;if(!action&&!record&&!finding)return;
  event.preventDefault();
  el.disabled=true;
  try{if(finding)await showFinding(finding);else if(record)await showRecord(record);else await dispatch(action,el);}
  catch(error){if(error.name!=='AbortError')toast(message(error),true);}
  finally{if(el.isConnected)el.disabled=false;}
});
document.addEventListener('submit',async event=>{
  const form=event.target;if(!(form instanceof HTMLFormElement))return;event.preventDefault();
  const submitButton=form.querySelector('button[type="submit"]'),errorElement=form.querySelector('.form-error')||(form.id==='auth-form'?$('#auth-error'):null);
  if(submitButton)submitButton.disabled=true;if(errorElement)errorElement.textContent='';
  try{await submit(form);}catch(error){if(error.name==='AbortError')return;if(errorElement&&errorElement.isConnected)errorElement.textContent=message(error);else toast(message(error),true);}
  finally{if(submitButton?.isConnected)submitButton.disabled=false;}
});
document.addEventListener('input',event=>{
  if(event.target.closest('#highlight-form'))rememberHighlightDraft();
  if(event.target.matches('#weights-form input[type="range"]'))event.target.nextElementSibling.value=event.target.value;
  if(event.target.matches('#universe-filters input[name="q"]')){clearTimeout(S.searchTimer);S.searchTimer=setTimeout(()=>{if(S.view==='universe')loadUniverse(S.epoch).catch(error=>{if(error.name!=='AbortError')universeError(error);});},280);}
});
document.addEventListener('change',async event=>{
  const el=event.target;
  try{
    if(el.closest('#watch-form'))updateWatchFields();
    if(el.matches('#vendor-form select[name="mode"]')){const file=el.value==='file';$('#vendor-url-field').hidden=file;$('#vendor-file-field').hidden=!file;$('#vendor-form').elements.url.required=!file;$('#vendor-form').elements.file.required=file;}
    if(el.id==='graphics-quality')S.universe?.setQuality(el.value);
    if(el.matches('#universe-filters select[name="severity"],#universe-filters select[name="group"],#universe-filters input[name="kev"]')){clearTimeout(S.searchTimer);await loadUniverse(S.epoch);}
    if(el.matches('#catalog-filters select,#catalog-filters input[name="kev"]'))await submit(el.form);
    if(el.matches('#trend-filters select'))await submit(el.form);
    if(el.id==='saved-filter'&&el.value!==''){const f=S.profile.filters[Number(el.value)];S.catalog={q:f.q||'',severity:f.severity||'all',kev:!!f.kev,days:f.days||'0',sort:f.sort||'priority',offset:0};await loadCatalog(S.epoch);}
  }catch(error){if(error.name!=='AbortError')toast(message(error),true);}
});
document.addEventListener('universeflightstart',()=>{setUniverseControls(false);closeUniverseSelection();});
document.addEventListener('universenewrecords',event=>{
  const el=$('#universe-new-observation');el.textContent=num(event.detail.count)+' newly indexed record'+(event.detail.count===1?'':'s')+' · data arrival, not live attacks';el.hidden=false;
  clearTimeout(S.newObservationTimer);S.newObservationTimer=setTimeout(()=>el.hidden=true,6000);
});
$('#dialog').addEventListener('close',()=>{S.graph?.dispose();S.graph=null;S.dialogEpoch=(S.dialogEpoch||0)+1;S.universe?.setVisible(S.view==='universe'&&$('#auth-view').hidden);});
document.addEventListener('fullscreenchange',()=>{
  const active=document.fullscreenElement===$('#universe-view'),button=$('#fullscreen-button');
  if(button)button.textContent=active?'Exit fullscreen':'Enter fullscreen';
  requestAnimationFrame(()=>S.universe?.setVisible(S.view==='universe'&&!$('#dialog').open));
});
window.addEventListener('hashchange',route);
document.addEventListener('visibilitychange',()=>S.universe?.setVisible(!document.hidden&&S.view==='universe'&&!$('#dialog').open));
hydrateIcons();
function installed(){return matchMedia('(display-mode: standalone)').matches||navigator.standalone===true;}
function updateInstallButton(){
  const button=$('#install-app-button');if(!button)return;
  const ios=/iPad|iPhone|iPod/.test(navigator.userAgent)||(navigator.platform==='MacIntel'&&navigator.maxTouchPoints>1);
  button.hidden=installed()||(!S.installPrompt&&!ios);
}
window.addEventListener('beforeinstallprompt',event=>{event.preventDefault();S.installPrompt=event;updateInstallButton();});
window.addEventListener('appinstalled',()=>{S.installPrompt=null;updateInstallButton();toast('MasterMonk installed.');});
if('serviceWorker' in navigator&&window.isSecureContext){window.addEventListener('load',()=>navigator.serviceWorker.register('/service-worker.js',{scope:'/'}).catch(()=>{}));}
updateInstallButton();
async function boot(){
  try{
    const data=await api('/api/session');S.user=data.user;S.public=data.publicCatalog;S.setup=data.needsSetup;S.version=data.version;S.syncMode=data.syncMode;S.ai=data.ai;
    if(S.user)S.profile=await api('/api/profile');await route();
  }catch(error){$('#connection-error').hidden=false;$('#connection-error').textContent=message(error);$('#account-button').textContent='Disconnected';}
}
setInterval(async()=>{
  if(S.polling||document.hidden||$('#dialog').open||!$('#auth-view').hidden||document.activeElement?.matches('input,select,textarea'))return;
  S.polling=true;
  try{
    if(publicViews.includes(S.view)){
      const status=await api('/api/status'),signature=JSON.stringify(status);
      if(S.view==='universe')updateUniverseLiveStatus(status);
      const changed=status.revision!==S.revision,healthChanged=signature!==S.statusSignature;
      S.statusSignature=signature;
      if(changed||(['sources','discover'].includes(S.view)&&healthChanged)||(S.view==='learn'&&!S.learnRecord))await refreshView();
      S.revision=status.revision;
    }else if(S.user&&['workspace','watchlists'].includes(S.view))await refreshView();
  }catch(error){if(error.name!=='AbortError'){$('#collector-status').textContent='Refresh unavailable · '+message(error);}}
  finally{S.polling=false;}
},15000);
boot();
