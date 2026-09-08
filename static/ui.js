/* Small presentation helpers. Upstream text always passes through escapeHTML. */
export const $ = (selector, root=document) => root.querySelector(selector);
export const $$ = (selector, root=document) => Array.from(root.querySelectorAll(selector));
export const sourceNames = {cisa:"CISA KEV",nvd:"NVD",epss:"FIRST EPSS",github:"GitHub Advisory Database",cve:"CVE / CNA",osv:"OSV"};
const shapes = {
  refresh:'<path d="M20 7v5h-5M4 17v-5h5"/><path d="M6.1 7a7 7 0 0 1 11.7-2L20 8M4 16l2.2 3A7 7 0 0 0 18 17"/>',
  code:'<path d="m8 7-5 5 5 5m8-10 5 5-5 5m-3-14-2 18"/>',
  nodes:'<circle cx="12" cy="5" r="2"/><circle cx="5" cy="18" r="2"/><circle cx="19" cy="18" r="2"/><path d="m11 7-5 9m7-9 5 9M7 18h10"/>',
  target:'<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="4"/><path d="M12 2v4m0 12v4M2 12h4m12 0h4"/>',
  shield:'<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="M12 8v5m0 3v.2"/>',
  spark:'<path d="m12 3 2.4 6.6L21 12l-6.6 2.4L12 21l-2.4-6.6L3 12l6.6-2.4L12 3Z"/>',
  orbit:'<ellipse cx="12" cy="12" rx="10" ry="4.5" transform="rotate(-35 12 12)"/><ellipse cx="12" cy="12" rx="10" ry="4.5" transform="rotate(35 12 12)"/><circle cx="12" cy="12" r="1"/>',
  list:'<path d="M8 5h13M8 12h13M8 19h13M3 5h.1M3 12h.1M3 19h.1"/>',
  search:'<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
  reset:'<path d="M4 5v6h6M4.5 11a8 8 0 1 1 1 7"/>',
  arrow:'<path d="M4 12h16m-6-6 6 6-6 6"/>',
  plus:'<path d="M5 12h14M12 5v14"/>',
  minus:'<path d="M5 12h14"/>',
  pause:'<path d="M8 5v14M16 5v14"/>',
  play:'<path d="m8 4 12 8-12 8V4Z"/>',
  expand:'<path d="M9 3H3v6m12-6h6v6M3 15v6h6m12-6v6h-6"/>',
  download:'<path d="M12 3v12m-5-5 5 5 5-5M4 17v4h16v-4"/>',
  clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  package:'<path d="m12 3 9 5v9l-9 5-9-5V8l9-5Zm0 10v9M3 8l9 5 9-5M7.5 5.5l9 5"/>',
  fingerprint:'<path d="M5 10a7 7 0 0 1 14 0v4m-11-4a4 4 0 0 1 8 0v7m-5-7a1 1 0 0 1 2 0v9M5 14v4m3-5v8m11-4v3"/>',
  wrench:'<path d="m14 5 3 3 4-4a7 7 0 0 1-8 9L6 20a2 2 0 0 1-3-3l7-7a7 7 0 0 1 8-8l-4 3Z"/>',
  close:'<path d="m6 6 12 12M6 18 18 6"/>',
  external:'<path d="M14 3h7v7m0-7L10 14M10 3H3v18h18v-7"/>',
  check:'<path d="m5 12 4 4L20 5"/>',
  alert:'<path d="m12 3 10 18H2L12 3Zm0 6v5m0 3v.2"/>',
  copy:'<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>'
};
export function icon(name) {
  // Intrinsic dimensions protect directly inserted icons even before CSS loads.
  return '<svg class="ui-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">' + (shapes[name] || shapes.nodes) + '</svg>';
}
export function hydrateIcons(root=document) {
  $$('[data-icon]',root).forEach(el => { el.innerHTML = icon(el.dataset.icon); });
}
export function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
export function link(url, label, className='reference-link') {
  try {
    const parsed = new URL(url);
    if (!['https:','http:'].includes(parsed.protocol) || parsed.username || parsed.password) return escapeHTML(label || url);
    return '<a href="' + escapeHTML(parsed.href) + '" target="_blank" rel="noopener noreferrer" class="' + className + '">' + escapeHTML(label || url) + '</a>';
  } catch { return escapeHTML(label || url || 'Source URL unavailable'); }
}
export function num(value) {
  return typeof value === 'number' && Number.isFinite(value) ? new Intl.NumberFormat('en').format(value) : '—';
}
export function metric(value, decimals=1) {
  return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(decimals) : 'Unknown';
}
export function percent(value) {
  return typeof value === 'number' && Number.isFinite(value) ? (value * 100).toFixed(2) + '%' : 'Unknown';
}
export function date(value, withTime=false) {
  if (!value) return 'Not supplied';
  const d=new Date(value);
  if (!Number.isFinite(d.getTime())) return 'Not supplied';
  return new Intl.DateTimeFormat('en-GB',{day:'2-digit',month:'short',year:'numeric',timeZone:'UTC',...(withTime?{hour:'2-digit',minute:'2-digit',hour12:false}:{})}).format(d) + (withTime?' UTC':'');
}
export function age(value) {
  if (!value) return 'Not fetched';
  const time = new Date(value).getTime();
  if (!Number.isFinite(time)) return 'Not supplied';
  const seconds = Math.floor((Date.now()-time)/1000);
  if(seconds < -120) return date(value);
  if(seconds < 60) return 'Just now';
  if(seconds < 3600) return Math.floor(seconds/60) + 'm ago';
  if(seconds < 86400) return Math.floor(seconds/3600) + 'h ago';
  return Math.floor(seconds/86400) + 'd ago';
}
export function severityPill(record) {
  const kind = record.severity || 'Unknown';
  const tone = {Critical:'purple',High:'amber',Medium:'blue',Low:'blue'}[kind] || '';
  return '<span class="pill '+tone+'-pill">' + escapeHTML(kind) + '</span>';
}
export function priorityMarkup(record) {
  const score=record.priority?.score;
  if(typeof score!=='number'||!Number.isFinite(score))return '<span class="muted">Unknown</span>';
  return '<span class="score"><span class="score-line"><i style="width:'+Math.max(0,Math.min(100,score))+'%"></i></span>'+num(score)+'</span><span class="subcell">'+escapeHTML(record.priority?.band||'Unknown')+'</span>';
}
export function empty(title, description, action='') {
  return '<div class="empty-state"><span>'+icon('orbit')+'</span><h3>'+escapeHTML(title)+'</h3><p>'+escapeHTML(description)+'</p>'+action+'</div>';
}
export function recordTable(records) {
  if(!records.length) return empty('No matching observations','Try another filter, or inspect Sources to see which feeds have responded.');
  return '<div class="table-scroll"><table><thead><tr><th scope="col">Vulnerability</th><th scope="col">Severity</th><th scope="col">CVSS</th><th scope="col">EPSS · 30 days</th><th scope="col">Priority</th><th scope="col">Evidence</th></tr></thead><tbody>'+
    records.map(r=>'<tr><td><button type="button" class="record-button" '+(r.findingId?'data-finding="'+escapeHTML(r.findingId):'data-record="'+escapeHTML(r.id))+'"><span class="record-id">'+escapeHTML(r.id)+'</span><strong>'+escapeHTML(r.title)+'</strong></button><span class="subcell">'+escapeHTML(r.vendor)+' · '+escapeHTML(r.product)+'</span></td>'+
      '<td>'+severityPill(r)+(r.withdrawn?'<span class="subcell coral">Withdrawn / rejected</span>':'')+'</td><td class="metric">'+metric(r.cvss)+'<span class="subcell">'+escapeHTML(sourceNames[r.cvssSource]||'No metric')+'</span></td>'+
      '<td class="metric">'+percent(r.epss)+'<span class="subcell">'+(r.epssDate?date(r.epssDate):'No daily score')+'</span></td><td>'+priorityMarkup(r)+'</td><td>'+(r.kev?'<span class="pill coral-pill">KEV</span>':'<span class="muted">No KEV observation</span>')+'<span class="subcell">'+num((r.sourceIds||[]).length)+' sources</span></td></tr>').join('')+'</tbody></table></div>';
}
export function eventMarkup(item) {
  const kinds={first_observed:'First observed by this source',exploitation_changed:'Exploitation evidence changed',remediation_changed:'Remediation information changed',catalog_removed:'Removed from the current KEV catalog',source_updated:'Source record updated'};
  const changes=item.changes||[];
  const pretty=value=>value===undefined || value===null ? 'Not supplied' : typeof value==='string'?value:JSON.stringify(value,null,2);
  const diff=value=>{const text=pretty(value);return escapeHTML(text.slice(0,12000))+(text.length>12000?'\n[Display shortened; consult the source record for complete content.]':'');};
  return '<details class="change" data-event="'+escapeHTML(item.id)+'"><summary><span class="event-icon">'+icon(item.kind==='exploitation_changed'?'target':item.kind==='remediation_changed'?'wrench':'refresh')+'</span><span><span class="event-title"><b class="record-id">'+escapeHTML(item.cve)+'</b> · '+escapeHTML(kinds[item.kind]||item.kind)+'</span><span class="event-meta">'+escapeHTML(sourceNames[item.source]||item.source)+(changes.length?' · '+changes.length+' changed fields':'')+'</span></span><time class="event-time" datetime="'+escapeHTML(item.observedAt)+'">'+date(item.observedAt,true)+'</time></summary>'+
    '<div class="change-body"><button type="button" class="text-button" data-record="'+escapeHTML(item.cve)+'">Investigate record '+icon('arrow')+'</button><p class="footnote">Observed locally '+date(item.observedAt,true)+'. Source timestamp: '+date(item.sourceTime,true)+'.</p>'+
    (changes.length?changes.map(c=>'<div class="diff"><strong>'+escapeHTML(c.field)+'</strong><div class="diff-values"><div><small>BEFORE</small><pre>'+diff(c.before)+'</pre></div><div><small>AFTER</small><pre>'+diff(c.after)+'</pre></div></div></div>').join(''):'<p class="footnote">This is the first saved observation from this source after its baseline. No earlier local version exists to compare.</p>')+'</div></details>';
}
export async function api(url, options={}) {
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),65000);
  const cancel=()=>controller.abort();
  options.signal?.addEventListener('abort',cancel,{once:true});
  try {
    if(options.signal?.aborted) controller.abort();
    const response=await fetch(url,{...options,headers:{Accept:'application/json',...(options.body?{'Content-Type':'application/json'}:{}),...options.headers},signal:controller.signal});
    let data;
    try{data=await response.json();}catch{throw new Error('The server returned an unreadable response. Check the application log.');}
    if(!response.ok) throw new Error(data.error||'The request failed (HTTP '+response.status+').');
    return data;
  } finally {clearTimeout(timer);options.signal?.removeEventListener('abort',cancel);}
}
export const post=(url,body={})=>api(url,{method:'POST',body:JSON.stringify(body)});
