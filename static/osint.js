/* Views derived from collected publisher records. No generated record content. */
import {escapeHTML as esc,icon,link,num,metric,percent,date,age,severityPill,empty,sourceNames} from './ui.js';

const action=(label,name,extra='',kind='quiet')=>'<button type="button" class="'+kind+'" data-action="'+name+'" '+extra+'>'+label+'</button>';
const sourceName=id=>sourceNames[id]||id||'Publisher';
const fact=(label,value)=>'<div><dt>'+label+'</dt><dd>'+value+'</dd></div>';
const references=r=>r.references||[];

export function sourceStrip(data){
  const sources=data.sources||[];
  return '<section class="collection-strip" aria-label="Source collection status">'+sources.map(s=>
    '<a href="#sources" class="collection-source" title="'+esc(s.message||s.coverage||'')+'"><span class="status-dot '+esc(s.state)+'"></span><strong>'+esc(sourceName(s.id))+'</strong><small>'+
    (s.state==='error'?'Needs attention':s.state==='running'?'Collecting…':s.lastSuccess?age(s.lastSuccess):['cve','osv'].includes(s.id)?'On investigation':'Waiting for response')+'</small></a>').join('')+'</section>';
}

export function recordCard(r,mode='published'){
  return '<article class="discovery-record"><div class="split"><button type="button" class="text-button record-id" data-record="'+esc(r.id)+'">'+esc(r.id)+'</button>'+severityPill(r)+'</div>'+
    '<h3><button type="button" class="record-button" data-record="'+esc(r.id)+'">'+esc(r.title||r.id)+'</button></h3>'+
    '<p class="muted">'+esc(r.vendor||'Vendor not supplied')+(r.product?' · '+esc(r.product):'')+'</p>'+
    '<div class="record-signals"><span>CVSS <b>'+metric(r.cvss)+'</b></span><span>EPSS <b>'+percent(r.epss)+'</b></span>'+(r.kev?'<span class="pill coral-pill">CISA KEV</span>':'')+'</div>'+
    '<p class="subcell">'+(mode==='kev'?'Added to KEV '+date(r.kevAdded):'Published '+date(r.published))+' · '+esc((r.sourceIds||[]).map(sourceName).join(' + '))+'</p>'+
    '<div class="button-row">'+action('Investigate '+icon('arrow'),'open-record','data-id="'+esc(r.id)+'"','text-button')+action('Learn with this record','learn-record','data-id="'+esc(r.id)+'"','text-button')+'</div></article>';
}

export function discoveryMarkup(data){
  const stats=data.stats,records=(data.records||[]).filter(r=>r.published&&Number.isFinite(Date.parse(r.published))&&Date.parse(r.published)<=Date.now());
  let html='<section class="discovery-intro"><div><span class="kicker">OPEN-SOURCE VULNERABILITY INTELLIGENCE</span><h2>What has been disclosed?<br>What does the evidence tell us?</h2><p>Follow new CVEs, compare their sources, and work through an investigation with the record in front of you.</p><div class="button-row"><a class="button-link primary" href="#universe">Explore the universe '+icon('orbit')+'</a><a class="button-link" href="#learn">Learn to investigate '+icon('arrow')+'</a></div></div><form id="lookup-form" class="lookup-panel"><label for="lookup-id">Investigate a CVE or GitHub advisory</label><input id="lookup-id" name="id" required maxlength="120" placeholder="Paste a CVE or GHSA identifier" autocomplete="off" spellcheck="false"><p class="muted">Open saved evidence or fetch the publisher record for an identifier you provide.</p><p class="form-error" role="alert"></p><button type="submit" class="primary">Investigate record '+icon('arrow')+'</button></form></section>';
  html+=sourceStrip(data)+'<div class="stat-strip">'+[['Collected records',stats.total],['Known exploited',stats.kev],['Critical severity',stats.critical],['Published this week',stats.newWeek]].map(([name,value])=>'<div class="stat"><b>'+num(value)+'</b><span>'+name+'</span></div>').join('')+'</div>';
  if(!stats.total)return html+empty('Collecting the first source records','CISA KEV, GitHub Advisories, and NVD populate this catalog as their requests complete. This page updates automatically.',action('Check collection progress','sources','','primary'));
  html+='<div class="discovery-columns"><section><div class="section-heading"><div><span class="kicker">LATEST PUBLISHED IN YOUR CATALOG</span><h2>New disclosures</h2></div><button type="button" class="text-button" data-action="latest-catalog">Browse all '+icon('arrow')+'</button></div><div class="discovery-grid">'+(records.length?records.map(r=>recordCard(r)).join(''):empty('Waiting for published disclosures','The latest feed fills when GitHub or NVD supplies publisher dates. Collected KEV entries are available alongside it.'))+'</div></section><aside><div class="section-heading"><div><span class="kicker">CISA EXPLOITATION EVIDENCE</span><h2>Recent KEV additions</h2></div></div>'+(data.radar?.length?data.radar.map(r=>recordCard(r,'kev')).join(''):empty('Waiting for the KEV catalog','The CISA collection status appears above.'))+'</aside></div>';
  return html+'<p class="muted"><small>Publisher dates determine this feed’s order. Last successful collection: '+date(data.lastSuccess,true)+'. Saved observation history begins '+date(data.baseline)+'.</small></p>';
}

export function recordSummary(r){
  return '<h3 class="record-heading">'+esc(r.title||r.id)+'</h3><div class="button-row">'+severityPill(r)+(r.kev?'<span class="pill coral-pill">CISA KEV</span>':'')+(r.withdrawn?'<span class="pill amber-pill">Withdrawn / rejected</span>':'')+'</div>'+
    '<p class="muted">'+esc(r.vendor||'Vendor not supplied')+(r.product?' / '+esc(r.product):'')+'</p>'+
    '<div class="metric-grid"><div><span>CVSS · technical severity</span><strong>'+metric(r.cvss)+'</strong><small>'+esc(r.cvssSource?sourceName(r.cvssSource):'Not supplied')+'</small></div><div><span>EPSS · next 30 days</span><strong>'+percent(r.epss)+'</strong><small>'+date(r.epssDate)+'</small></div><div><span>Triage priority · calculated</span><strong>'+num(r.priority?.score)+'</strong><small>'+esc(r.priority?.band||'Unknown')+'</small></div><div><span>Published</span><strong>'+date(r.published)+'</strong><small>Updated '+date(r.modified)+'</small></div></div>';
}

export function overviewMarkup(r){
  return '<section><h3>What was disclosed</h3><p class="record-description">'+esc(r.description||'The publisher has not supplied a description.')+'</p>'+
    (r.vector?'<p><code class="vector">'+esc(r.vector)+'</code></p>':'')+
    (r.cwes?.length?'<div class="button-row">'+r.cwes.map(c=>'<span class="pill">'+esc(c)+'</span>').join('')+'</div>':'')+'</section>'+
    (r.conflicts?.length?'<div class="notice warning"><h4>Source disagreement</h4>'+r.conflicts.map(c=>'<p>'+esc(c)+'</p>').join('')+'</div>':'')+
    '<div class="split-panels spaced"><section class="panel"><h3>Exploitation evidence</h3><p>'+(r.kev?'CISA lists '+esc(r.id)+' as known exploited. Added '+date(r.kevAdded)+'.':'No KEV listing is present in the saved observations for '+esc(r.id)+'.')+'</p><p>'+num(references(r).filter(ref=>ref.kind==='exploit').length)+' publisher-tagged exploit references.</p><p class="muted">Ransomware association: '+esc(r.ransomware||'Not supplied')+'.</p>'+action('Inspect source evidence','record-tab','data-tab="evidence"')+'</section>'+
    '<section class="panel"><h3>Where to investigate next</h3><p>'+esc(r.requiredAction||'Read the publisher’s affected-product conditions and remediation guidance. Compare versions, prerequisites, and supported release branches.')+'</p>'+
    (r.dueDate?'<p class="muted">CISA catalog due date: '+date(r.dueDate)+'; this is the catalog’s federal action deadline.</p>':'')+action('Affected software & fixes','record-tab','data-tab="packages"')+'</section></div>'+
    '<div class="learning-invite"><div><h3>Understand this record, step by step</h3><p>Identify the issue, interpret its scores, examine exploitation evidence, and plan an investigation.</p></div>'+action('Learn with '+esc(r.id),'learn-record','data-id="'+esc(r.id)+'"','primary')+'</div>';
}

export function evidenceMarkup(r){
  return '<h3>Source observations</h3><div class="source-evidence-grid">'+(r.sources||[]).map(s=>'<article class="panel"><h4>'+esc(sourceName(s.id))+'</h4><p>'+link(s.url,'Open source record '+s.key)+'</p><dl class="evidence-facts">'+fact('Observed',date(s.observedAt,true))+fact('Publisher update',date(s.modified,true))+fact('Source CVSS',metric(s.cvss))+'</dl>'+(s.withdrawn?'<span class="pill amber-pill">Source marks this withdrawn</span>':'')+'</article>').join('')+'</div>'+
    '<h3 class="spaced">Publisher references</h3>'+(references(r).length?'<ul class="reference-list">'+references(r).map(ref=>'<li><span class="pill">'+esc(ref.kind||'reference')+'</span> '+link(ref.url,ref.url)+'<span class="subcell">Attributed to '+esc(sourceName(ref.source))+'</span></li>').join('')+'</ul>':empty('No reference links supplied','The saved source observations do not include additional reference links.'));
}

export function packageEvidence(packages=[]){
  if(!packages.length)return empty('No structured product ranges supplied yet','Use the linked vendor advisory, or refresh this record’s publisher evidence to check for additional affected-product information.');
  return '<div class="table-scroll"><table><thead><tr><th>Affected software</th><th>Published affected range</th><th>Published fixed release</th><th>Source</th></tr></thead><tbody>'+packages.map(p=>'<tr><td><strong>'+esc(p.name||p.product||'Publisher product')+'</strong><span class="subcell">'+esc(p.ecosystem||'')+'</span></td><td class="range-cell">'+esc(p.affected||'See publisher record')+'</td><td class="range-cell">'+esc(p.fixed||'Not supplied')+'</td><td>'+link(p.url,sourceName(p.source))+'</td></tr>').join('')+'</tbody></table></div><p class="muted spaced">Read each affected range alongside its fixed release; different branches can have different fixes.</p>';
}

export function recordGraphModel(r){
  const nodes=[],edges=[];
  const add=(id,label,kind,column,source,detail)=>{nodes.push({id,label,kind,column,source,detail});return id;};
  const edge=(from,to,label,source)=>edges.push({from,to,label,source});
  const center=add('record',r.id,'vulnerability',1,r.sources?.[0]?.url||'',r.title||r.id);
  for(const [index,s] of (r.sources||[]).entries()){
    const id=add('source-'+index,sourceName(s.id),'advisory',0,s.url,'Source observation saved '+date(s.observedAt,true)+'. Publisher update '+date(s.modified,true)+'.'+(typeof s.cvss==='number'?' Source CVSS '+metric(s.cvss)+'.':''));
    edge(id,center,'Publisher observation for this record',s.url);
  }
  (r.packages||[]).slice(0,16).forEach((p,index)=>{
    const id=add('product-'+index,p.name||p.product||'Publisher product','package',2,p.url,(p.ecosystem?p.ecosystem+'. ':'')+'Affected: '+(p.affected||'See publisher record'));
    edge(center,id,'Publisher lists affected software',p.url);
    if(p.fixed){const fix=add('fix-'+index,p.fixed,'fix',3,p.url,'Published fixed release for '+(p.name||p.product)+'. Check the affected range for branch applicability.');edge(id,fix,'Publisher reports fixed release',p.url);}
  });
  if(r.kev){const url=r.sources?.find(s=>s.id==='cisa')?.url||'';const kev=add('kev','CISA KEV','exploitation',2,url,'Added '+date(r.kevAdded)+'. '+(r.requiredAction||''));edge(center,kev,'CISA lists known exploitation',url);}
  references(r).filter(ref=>['exploit','patch','advisory','vendor-advisory'].includes(ref.kind)).slice(0,14).forEach((ref,index)=>{
    let host='Publisher reference';try{host=new URL(ref.url).hostname;}catch{}
    const id=add('reference-'+index,(ref.kind==='exploit'?'Exploit reference':ref.kind==='patch'?'Patch reference':'Advisory')+' · '+host,ref.kind==='exploit'?'exploitation':ref.kind==='patch'?'fix':'advisory',3,ref.url,'Reference tagged '+ref.kind+' by '+sourceName(ref.source)+'.');
    edge(center,id,'Source-tagged '+ref.kind+' reference',ref.url);
  });
  return {nodes,edges,limited:(r.packages||[]).length>16||references(r).filter(ref=>['exploit','patch','advisory','vendor-advisory'].includes(ref.kind)).length>14};
}

function vectorFacts(r){
  const vector=r.vector||'',fields=/^CVSS:[34]\./.test(vector)?Object.fromEntries(vector.split('/').slice(1).map(part=>part.split(':'))):{};
  const meanings={AV:['Attack vector',{N:'Network',A:'Adjacent network',L:'Local access',P:'Physical access'}],AC:['Attack complexity',{L:'Low',H:'High'}],
    PR:['Privileges required',{N:'None',L:'Low',H:'High'}],UI:['User interaction',{N:'None',R:'Required',P:'Passive',A:'Active'}]};
  return Object.entries(meanings).filter(([key,[,values]])=>Object.hasOwn(values,fields[key])).map(([key,[label,values]])=>({
    label,value:values[fields[key]],detail:key+':'+fields[key]+' is the value supplied in the collected CVSS vector.'}));
}

function learnCard(card,index,active){
  return '<button type="button" class="learn-evidence-card" data-action="learn-focus" data-focus="'+index+'" aria-pressed="'+(active===index)+'"><small>'+esc(card.label)+'</small><strong>'+esc(card.value)+'</strong><span>'+icon('arrow')+'</span></button>';
}

export function learningBrief(r){
  const fixes=[...new Set((r.packages||[]).map(p=>p.fixed).filter(Boolean))],sources=(r.sources||[]).map(s=>sourceName(s.id)+' — '+s.url);
  return ['MasterMonk investigation brief',r.id+' — '+(r.title||r.id),'',
    'Vendor / product: '+([r.vendor,r.product].filter(Boolean).join(' / ')||'Not supplied'),
    'Published: '+date(r.published),'Last publisher update: '+date(r.modified),
    'CVSS: '+metric(r.cvss)+' ('+(r.severity||'Unknown')+')','CVSS vector: '+(r.vector||'Not supplied'),
    'EPSS: '+percent(r.epss)+' · score date '+date(r.epssDate),
    'CISA KEV: '+(r.kev?'Listed · added '+date(r.kevAdded):'No listing in the saved CISA observation'),
    'Affected software statements: '+num((r.packages||[]).length),'Published fixed releases: '+(fixes.join(', ')||'Not supplied'),
    'Published response guidance: '+(r.requiredAction||'Not supplied'),'',
    'Collected source records:',...(sources.length?sources:['Not supplied'])].join('\n');
}

export function learningMarkup(r,step=0,state={}){
  const steps=['Disclosure','Severity','Exploitation','Response'],sourceLinks=(r.sources||[]).filter(s=>s.id!=='epss').map(s=>link(s.url,sourceName(s.id))).join(' · ')||'No original source links were supplied in this collected record.';
  const exploitRefs=references(r).filter(ref=>ref.kind==='exploit'),vendorRefs=references(r).filter(ref=>['patch','advisory','vendor-advisory'].includes(ref.kind));
  const fixes=[...new Set((r.packages||[]).map(p=>p.fixed).filter(Boolean))];
  const panels=[
    {title:'Read the disclosure like an investigator',prompt:'Select each evidence card and separate what the publisher states from what remains unknown.',cards:[
      {label:'Disclosure',value:r.id,detail:r.description||'The collected source did not supply a description.'},
      {label:'Vendor / product',value:[r.vendor,r.product].filter(Boolean).join(' / ')||'Not supplied',detail:'This value comes from the merged collected source observations.'},
      {label:'Published / updated',value:date(r.published)+' / '+date(r.modified),detail:'Publisher dates are different from the date this MasterMonk instance collected the record.'},
      {label:'Weakness identifiers',value:(r.cwes||[]).join(', ')||'Not supplied',detail:'CWE identifiers classify the weakness when a publisher supplies them.'}],
      checks:['Open at least one original source record.','Confirm the named product and vulnerability behavior.','Record any missing affected-version or configuration details.']},
    {title:'Decode the technical conditions',prompt:'Use the collected score and vector to understand reachability and prerequisites. EPSS answers a different question.',cards:[
      {label:'CVSS / severity',value:metric(r.cvss)+' · '+(r.severity||'Unknown'),detail:'Technical severity supplied by '+(r.cvssSource?sourceName(r.cvssSource):'an unspecified source')+'.'},
      {label:'EPSS · next 30 days',value:percent(r.epss),detail:'FIRST EPSS score dated '+date(r.epssDate)+'. It is a probability estimate, not confirmation of exploitation.'},...vectorFacts(r)],
      checks:['Identify required access from the vector.','Identify required privileges and user interaction.','Compare the CVSS and EPSS source dates.']},
    {title:'Test every exploitation claim',prompt:'Use attribution and dates to distinguish confirmed KEV evidence, probability, and publisher-tagged references.',cards:[
      {label:'CISA KEV',value:r.kev?'Listed':'No saved listing',detail:r.kev?'CISA KEV addition date: '+date(r.kevAdded)+'. '+(r.requiredAction||''):'The saved CISA observation does not list this record. That does not prove exploitation is impossible.'},
      {label:'EPSS probability',value:percent(r.epss),detail:'Score date: '+date(r.epssDate)+'. Treat this separately from known exploitation evidence.'},
      {label:'Exploit references',value:num(exploitRefs.length),detail:exploitRefs.length?exploitRefs.map(ref=>ref.url).join(' · '):'No publisher-tagged exploit references are present in the collected record.'},
      {label:'Source coverage',value:num((r.sources||[]).length)+' observations',detail:(r.sources||[]).map(s=>sourceName(s.id)+' · observed '+date(s.observedAt,true)).join(' | ')||'No source observations supplied.'}],
      checks:['Open the CISA record when KEV is listed.','Inspect what each exploit reference actually claims.','Keep probability, public exploit material, and confirmed exploitation separate.']},
    {title:'Build a response you can explain',prompt:'Connect applicability, remediation, and evidence gaps into a concise investigation brief.',cards:[
      {label:'Affected statements',value:num((r.packages||[]).length),detail:(r.packages||[]).slice(0,8).map(p=>(p.name||p.product||'Product')+': '+(p.affected||'See publisher record')).join(' | ')||'No structured affected-product range was supplied.'},
      {label:'Published fixed releases',value:fixes.join(', ')||'Not supplied',detail:fixes.length?'These releases are reported in collected package evidence. Confirm the applicable product branch.':'Use the publisher advisory; do not infer a fixed version.'},
      {label:'Response guidance',value:r.requiredAction||'Open publisher guidance',detail:r.dueDate?'CISA federal action due date: '+date(r.dueDate)+'.':'No CISA due date is present in the collected record.'},
      {label:'Publisher references',value:num(vendorRefs.length),detail:vendorRefs.length?vendorRefs.map(ref=>ref.url).join(' · '):'No patch or vendor-advisory references are tagged in the collected record.'}],
      checks:['Verify the affected version and configuration.','Choose only a publisher-supported fix or mitigation.','Preserve source links, dates, and unresolved evidence gaps.']}
  ];
  const panel=panels[step],focus=Math.max(0,Math.min(panel.cards.length-1,Number(state.focus)||0)),selected=panel.cards[focus];
  const completed=new Set(state.checks||[]),stepChecks=panel.checks.map((text,index)=>({text,key:step+'-'+index,done:completed.has(step+'-'+index)}));
  const progress=Math.round((step+stepChecks.filter(item=>item.done).length/stepChecks.length)/steps.length*100);
  return '<div class="learn-record-header"><div><span class="kicker">REAL-RECORD INVESTIGATION LAB</span><h2>'+esc(r.id)+'</h2><p>'+esc(r.title)+'</p></div><div class="button-row">'+action('Open full evidence','open-record','data-id="'+esc(r.id)+'"')+action('Choose another record','learn-choose')+'</div></div>'+
    '<section class="learn-lab"><nav class="learn-route" aria-label="Investigation stages">'+steps.map((name,index)=>'<button type="button" data-action="learn-step" data-step="'+index+'" aria-current="'+(step===index?'step':'false')+'"><span>'+String(index+1).padStart(2,'0')+'</span><strong>'+name+'</strong></button>').join('')+'</nav>'+
    '<div class="learn-progress" role="progressbar" aria-label="Investigation progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="'+progress+'"><span style="width:'+progress+'%"></span></div>'+
    '<div class="learn-workbench"><section class="learn-board"><span class="kicker">STAGE '+(step+1)+' OF '+steps.length+'</span><h2>'+panel.title+'</h2><p>'+panel.prompt+'</p><div class="learn-card-grid">'+panel.cards.map((card,index)=>learnCard(card,index,focus)).join('')+'</div><article class="learn-inspector"><span class="kicker">SELECTED EVIDENCE</span><h3>'+esc(selected.label)+' · '+esc(selected.value)+'</h3><p>'+esc(selected.detail)+'</p></article></section>'+
    '<aside class="learn-notebook"><span class="kicker">INVESTIGATION CHECKS</span><h3>'+stepChecks.filter(item=>item.done).length+' / '+stepChecks.length+' verified</h3><div class="learn-checks">'+stepChecks.map(item=>'<button type="button" data-action="learn-check" data-check="'+item.key+'" aria-pressed="'+item.done+'"><span aria-hidden="true">'+(item.done?'✓':'○')+'</span>'+esc(item.text)+'</button>').join('')+'</div><div class="learn-sources"><span class="kicker">OPEN ORIGINAL SOURCES</span><p>'+sourceLinks+'</p></div>'+
    '<div class="learn-navigation"><button type="button" data-action="learn-step" data-step="'+Math.max(0,step-1)+'"'+(!step?' disabled':'')+'>Previous</button>'+(step===steps.length-1?'<button type="button" class="primary" data-action="learn-copy">Copy investigation brief</button>':'<button type="button" class="primary" data-action="learn-step" data-step="'+(step+1)+'">Next stage '+icon('arrow')+'</button>')+'</div></aside></div></section>';
}
