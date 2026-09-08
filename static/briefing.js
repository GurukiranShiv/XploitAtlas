/* Presentation only: callers supply collected records, stored differences, or explicitly labelled AI output. */
import {escapeHTML as esc,link,date,num,metric,percent,severityPill,empty} from './ui.js';

export function comparisonForm(range){
  return '<section class="panel comparison-command"><span class="kicker">TWO DATES · ONE BRIEFING</span><h2>What changed between…</h2>'+
    '<form id="comparison-form" class="toolbar"><label>From (UTC, inclusive)<input type="date" name="from" required value="'+esc(range.from)+'"></label><label>To (UTC, inclusive)<input type="date" name="to" required value="'+esc(range.to)+'"></label><button type="submit" class="primary">Compare saved evidence</button><p class="form-error" role="alert"></p></form>'+
    '<div id="comparison-results">'+(range.result?comparisonMarkup(range.result):'<p class="muted">Select a period to compare recorded evidence. This does not reconstruct days before collection began.</p>')+'</div></section>';
}

function displayValue(value){
  if(value===null||value===undefined)return 'Not supplied';
  if(typeof value==='boolean')return value?'Yes':'No';
  return typeof value==='string'?value:JSON.stringify(value,null,2);
}

export function comparisonMarkup(data){
  const labels={indexed:'First indexed',kevAdded:'KEV additions observed',remediation:'Remediation updated',evidence:'Evidence updated'};
  let html='<p class="comparison-range">'+esc(data.from)+' → '+esc(data.to)+' · UTC observation dates</p>'+
    (data.outsideHistory?'<p class="notice">History starts '+date(data.availableFrom)+'. Earlier dates are unavailable, not zero.</p>':'')+
    '<div class="comparison-grid">'+Object.entries(labels).map(([key,label])=>{
      const group=data.groups[key];return '<section><span class="kicker">'+label+'</span><strong class="comparison-total">'+num(group.total)+'</strong><p>'+esc(data.definitions[key])+'</p>'+
        (group.records.length?'<details><summary>Investigate '+num(group.records.length)+' records'+(group.truncated?' shown':'')+'</summary><ul class="comparison-records">'+group.records.map(r=>'<li><button type="button" data-record="'+esc(r.id)+'">'+esc(r.id)+'</button><span>'+esc(r.title)+'</span><small>Observed '+date(r.observedAt,true)+'</small></li>').join('')+'</ul></details>':'<span class="muted">No matching saved observations.</span>')+'</section>';
    }).join('')+'</div><p class="muted"><small>Categories overlap. Record summaries show current collected evidence. A remediation update does not mean your software was fixed.</small></p>';
  if(data.differences.length){
    html+='<h3>Read the recorded before → after</h3><div class="comparison-differences">'+data.differences.map(event=>'<details><summary>'+esc(event.id)+' · '+esc(event.source)+' · '+date(event.observedAt,true)+'</summary><div class="table-scroll"><table><thead><tr><th>Field</th><th>Before this observation</th><th>After this observation</th></tr></thead><tbody>'+event.fields.map(f=>'<tr><th>'+esc(f.field)+'</th><td><pre>'+esc(displayValue(f.before))+'</pre></td><td><pre>'+esc(displayValue(f.after))+'</pre></td></tr>').join('')+'</tbody></table></div><button type="button" data-record="'+esc(event.id)+'">Investigate record</button></details>').join('')+'</div>'+
      (data.differencesTruncated?'<p class="muted">Latest 50 change events shown. Narrow the dates or open a record’s saved history for more.</p>':'');
  }
  return html;
}

const componentEcosystems=['npm','PyPI','Maven','Go','crates.io','NuGet','Packagist','RubyGems'];
const componentOption=(value,current)=>'<option value="'+esc(value)+'"'+(value===current?' selected':'')+'>'+esc(value)+'</option>';

function componentFields(prefix,label,value){
  value=value||{};
  return '<fieldset class="component-side"><legend><span>'+(prefix==='LEFT'?'A':'B')+'</span>'+esc(label)+'</legend><label>Ecosystem<select name="'+prefix.toLowerCase()+'_ecosystem">'+componentEcosystems.map(item=>componentOption(item,value.ecosystem||'npm')).join('')+'</select></label><label>Package name<input name="'+prefix.toLowerCase()+'_name" required maxlength="200" value="'+esc(value.name||'')+'" autocomplete="off" spellcheck="false"></label><label>Exact version<input name="'+prefix.toLowerCase()+'_version" required maxlength="100" value="'+esc(value.version||'')+'" autocomplete="off" spellcheck="false"></label></fieldset>';
}

export function componentComparisonView(state,origin){
  return '<section class="component-lab"><div class="component-lab-intro"><span class="kicker">OSV EXACT-VERSION QUERY</span><h2>Put two components under the same lens.</h2><p>Compare two versions of one package or two different packages. Results come from current OSV package queries and collected enrichment; absence is reported as absence, not safety.</p></div><form id="component-compare-form" class="component-compare-form">'+componentFields('LEFT','Component A',state.left)+componentFields('RIGHT','Component B',state.right)+'<div class="component-run"><button type="submit" class="primary">Compare evidence</button><p class="form-error" role="alert"></p></div></form><div id="component-results">'+(state.result?componentComparisonMarkup(state.result,origin):'<div class="component-empty"><span>A</span><i>⇄</i><span>B</span><p>Enter exact package versions to reveal shared and one-sided advisory matches.</p></div>')+'</div></section>';
}

function componentLabel(component){
  return component.ecosystem+' · '+component.name+' @ '+component.version;
}

function componentRecords(group,heading,emptyText){
  return '<section class="component-delta-card"><span class="kicker">'+esc(heading)+'</span><strong>'+num(group.total)+'</strong>'+(group.records.length?'<ul>'+group.records.map(record=>'<li><button type="button" data-record="'+esc(record.id)+'"><span>'+esc(record.id)+'</span><small>'+esc(record.title||record.id)+'</small></button></li>').join('')+'</ul>':'<p>'+esc(emptyText)+'</p>')+(group.recordsTruncated?'<small>Response display is bounded; compare again after narrowing the component identity if coverage is marked incomplete.</small>':'')+'</section>';
}

function componentEvidence(view,side,origin){
  const absolute=origin.replace(/\/$/,'')+view.badgePath;
  const alt='MasterMonk OSV evidence for '+view.component.name+' '+view.component.version;
  const htmlCode='<img src="'+esc(absolute)+'" alt="'+esc(alt)+'">';
  const markdown='![MasterMonk OSV evidence]('+absolute+')';
  const severity=view.summary.severities||{};
  return '<article class="component-evidence"><header><span class="kicker">COMPONENT '+esc(side)+'</span><h3>'+esc(componentLabel(view.component))+'</h3><p>'+esc(view.message)+'</p></header><div class="component-metrics"><div><strong>'+num(view.summary.total)+'</strong><span>OSV matches</span></div><div><strong>'+num(view.summary.kev)+'</strong><span>CISA KEV</span></div><div><strong>'+num(severity.Critical||0)+'</strong><span>Critical</span></div><div><strong>'+num(severity.High||0)+'</strong><span>High</span></div></div>'+(view.partial||view.recordsTruncated?'<p class="notice">Coverage is incomplete; counts are lower bounds.</p>':'')+'<section class="component-badge"><span class="kicker">PUBLIC EVIDENCE BADGE</span><img src="'+esc(absolute)+'" alt="'+esc(alt)+'"><p>The URL performs the same exact-version check and is cached for five minutes. Package name and version are public in the URL.</p><label>HTML<textarea id="component-badge-'+side.toLowerCase()+'-html" readonly rows="3">'+esc(htmlCode)+'</textarea></label><button type="button" data-action="component-badge-copy" data-target="component-badge-'+side.toLowerCase()+'-html">Copy HTML</button><label>Markdown<textarea id="component-badge-'+side.toLowerCase()+'-markdown" readonly rows="3">'+esc(markdown)+'</textarea></label><button type="button" data-action="component-badge-copy" data-target="component-badge-'+side.toLowerCase()+'-markdown">Copy Markdown</button></section></article>';
}

export function componentComparisonMarkup(data,origin){
  return '<section class="component-result"><div class="component-coverage '+(data.complete?'complete':'partial')+'"><span class="kicker">'+(data.complete?'COMPLETE RESPONSE':'INCOMPLETE RESPONSE')+'</span><p>'+esc(data.notice)+'</p><small>Compared '+date(data.comparedAt,true)+'. Badge responses are refreshed independently.</small></div><div class="component-evidence-grid">'+componentEvidence(data.left,'A',origin)+componentEvidence(data.right,'B',origin)+'</div><div class="component-delta">'+componentRecords(data.onlyLeft,'ONLY COMPONENT A','No advisory identity appeared only for component A.')+componentRecords(data.common,'BOTH COMPONENTS','No advisory identity appeared in both exact-version responses.')+componentRecords(data.onlyRight,'ONLY COMPONENT B','No advisory identity appeared only for component B.')+'</div></section>';
}

export function highlightComposer(draft,pages){
  return '<section class="panel highlight-composer"><span class="kicker">YOUR CURATED READING LIST</span><h2>Make the important records easy to find.</h2><p>Open a vulnerability and choose <strong>Add to highlights</strong>. Select up to 24 collected records, then add your interpretation separately from the source evidence.</p>'+
    '<form id="highlight-form" class="stack"><label>Briefing title<input name="title" required maxlength="100" value="'+esc(draft.title||'')+'"></label><label>Why these records matter<textarea name="note" required maxlength="1200">'+esc(draft.note||'')+'</textarea></label>'+
    '<div class="highlight-draft">'+(draft.items.length?draft.items.map(r=>'<article><div class="split"><strong class="mono">'+esc(r.id)+'</strong><button type="button" data-action="highlight-remove" data-id="'+esc(r.id)+'">Remove</button></div><p>'+esc(r.title||r.id)+'</p><label>Your note (optional)<textarea name="item-'+esc(r.id)+'" data-highlight-id="'+esc(r.id)+'" maxlength="500">'+esc(r.note||'')+'</textarea></label></article>').join(''):empty('No records selected','Use Discover, Intelligence, or the Universe to choose real observations.'))+'</div>'+
    '<p class="notice">Creating the page enables a link for anyone who has it and can reach this instance. Notes are shared too. You can revoke the link below; no private inventory is included.</p><p class="form-error" role="alert"></p><button type="submit" class="primary"'+(!draft.items.length?' disabled':'')+'>Create shareable highlights</button></form></section>'+
    '<section class="panel"><h2>Your shared pages</h2>'+(pages.length?'<div class="highlight-pages">'+pages.map(p=>'<article><span class="kicker">'+num(p.count)+' RECORDS · '+(p.revoked?'LINK REVOKED':'LINK ENABLED')+'</span><h3>'+esc(p.title)+'</h3><p>'+esc(p.note)+'</p><div class="button-row">'+(!p.revoked?'<button type="button" data-action="highlight-open" data-token="'+esc(p.token)+'">Open page</button><button type="button" data-action="highlight-copy" data-token="'+esc(p.token)+'">Copy link</button>':'')+'<button type="button" data-action="highlight-state" data-id="'+esc(p.id)+'" data-mode="'+(p.revoked?'restore':'revoke')+'">'+(p.revoked?'Enable link':'Revoke link')+'</button><button type="button" data-action="highlight-state" data-id="'+esc(p.id)+'" data-mode="delete">Delete page</button></div></article>').join('')+'</div>':'<p class="muted">No highlight pages have been created by this account.</p>')+'</section>';
}

export function highlightPage(page){
  return '<article class="highlight-brief"><header><span class="kicker">CURATED HIGHLIGHTS · '+num(page.items.length)+' COLLECTED RECORDS</span><h2>'+esc(page.title)+'</h2><p class="highlight-curator-note">'+esc(page.note)+'</p><small>Author’s note · Created '+date(new Date(page.created*1000).toISOString(),true)+'</small></header><div class="highlight-card-grid">'+page.items.map(({record:r,note})=>'<section class="panel"><div class="split"><span class="record-id">'+esc(r.id)+'</span>'+severityPill(r)+'</div><h3>'+esc(r.title)+'</h3><p>CVSS '+metric(r.cvss)+' · EPSS '+percent(r.epss)+' · '+(r.kev?'Listed in collected CISA KEV':'Not listed in collected CISA KEV')+'</p>'+(note?'<blockquote><span class="kicker">AUTHOR’S NOTE</span><p>'+esc(note)+'</p></blockquote>':'')+'<button type="button" class="primary" data-record="'+esc(r.id)+'">Investigate evidence</button></section>').join('')+'</div><p class="muted">These are current collected records, not a frozen historical snapshot. Curator notes are opinions, not provider evidence. Collection last succeeded '+date(page.evidenceUpdated,true)+'.</p></article>';
}

export function taxonomyMarkup(data){
  const patterns=data.patterns||[];
  return '<section class="taxonomy-context"><span class="kicker">WEAKNESS → ATTACK PATTERN → TECHNIQUE</span><h3>Understand the type of mistake.</h3><p>'+esc(data.notice)+'</p><div class="button-row">'+(data.cwes||[]).map(id=>link('https://cwe.mitre.org/data/definitions/'+id.replace('CWE-','')+'.html',id)).join('')+'</div>'+
    (patterns.length?'<div class="taxonomy-grid">'+patterns.map(p=>'<article><span class="kicker">'+esc(p.id)+'</span><h4>'+link(p.url,p.name)+'</h4>'+(p.techniques.length?'<p class="muted">MITRE CAPEC taxonomy mappings:</p><ul>'+p.techniques.map(t=>'<li>'+link(t.url,t.id+' · '+t.name)+'</li>').join('')+'</ul>':'<p class="muted">No ATT&CK technique mapping supplied for this pattern.</p>')+'</article>').join('')+'</div>':'<p class="notice">No CAPEC pattern mapping is available for the supplied CWE identifiers.</p>')+
    '<p class="muted">'+link(data.source,'MITRE CAPEC source catalog')+(data.version?' · Version '+esc(data.version):'')+(data.retrievedAt?' · Retrieved '+date(data.retrievedAt,true):'')+' · Showing at most 24 related patterns. These class-level associations are not an observed exploit chain for this CVE.</p></section>';
}

export function aiIntro(status,user){
  return '<section class="ai-reading"><span class="kicker">OPTIONAL · AI READING AID</span><h3>A plain-English explanation, separate from the evidence.</h3><p>The model receives this public record and its source URLs. It does not receive your password, private inventory, or notes. AI can make factual mistakes even when it cites a source.</p>'+
    (!user?'<p class="notice">Sign in to use a configured model. All original evidence and the investigation lab remain available without AI.</p>':!status?.configured?'<p class="notice">No model is configured. An administrator can set MASTERMONK_AI_ENDPOINT and MASTERMONK_AI_MODEL, with an optional API key, then restart the server. A compatible local model can avoid API fees; no model is bundled.</p>':'<p>Configured model: <strong>'+esc(status.model)+'</strong> at '+esc(status.provider)+'. Provider charges may apply.</p><button type="button" class="primary" data-action="ai-generate">Send this record & generate explanation</button>')+'</section>';
}

export function aiMarkup(value){
  return '<article class="ai-reading"><span class="kicker">AI-GENERATED · NOT SOURCE EVIDENCE</span><p class="notice">Verify these statements against the linked sources. This output is not saved into the vulnerability record.</p><h3>In plain English</h3><p>'+esc(value.summary)+'</p><h3>Why it matters</h3><p>'+esc(value.whyItMatters)+'</p><h3>Questions for your investigation</h3><p>'+esc(value.investigationChecks)+'</p><h3>Supplied sources cited by the model</h3><ul>'+value.citations.map((url,index)=>'<li>'+link(url,'Source '+(index+1))+'</li>').join('')+'</ul><small>'+esc(value.model)+' · Generated '+date(value.generatedAt,true)+'</small></article>';
}
