import {$,escapeHTML as esc,recordTable,empty,num,date,sourceNames} from './ui.js';
import {rendererPresentation} from './renderer-status.js';
let snapshot,matching=[],offset=0,universe;
const pageSize=100;
function render(){
  if(!snapshot)return;
  const values=new FormData($('#site-filters')),q=String(values.get('q')||'').toLowerCase(),level=values.get('severity');
  matching=snapshot.records.filter(r=>(!q||(r.id+' '+r.title+' '+r.vendor+' '+r.product).toLowerCase().includes(q))&&(level==='all'||r.severity===level)&&(!values.get('kev')||r.kev));
  $('#site-results').innerHTML=recordTable(matching.slice(offset,offset+pageSize));
  $('#site-count').textContent=num(matching.length?offset+1:0)+'–'+num(Math.min(offset+pageSize,matching.length))+' of '+num(matching.length)+' records in this snapshot';
  $('#site-previous').disabled=!offset;$('#site-next').disabled=offset+pageSize>=matching.length;
  universe?.setRecords(matching);
}
$('#site-filters').addEventListener('submit',event=>{event.preventDefault();offset=0;render();});
$('#site-filters').addEventListener('change',event=>{if(event.target.matches('select,input[type="checkbox"]')){offset=0;render();}});
let searchTimer;$('#site-filters input[name="q"]').addEventListener('input',()=>{clearTimeout(searchTimer);searchTimer=setTimeout(()=>{offset=0;render();},280);});
$('#site-previous').addEventListener('click',()=>{offset=Math.max(0,offset-pageSize);render();});
$('#site-next').addEventListener('click',()=>{offset+=pageSize;render();});
document.addEventListener('click',event=>{const button=event.target.closest('[data-record]');if(button){const record=snapshot.records.find(r=>r.id===button.dataset.record);if(record?.pagePath?.startsWith('vulnerability/'))location.href='./'+record.pagePath;}});
$('#show-universe').addEventListener('click',async()=>{
  if(!snapshot)return;
  try{
    $('#site-universe').hidden=false;
    if(!universe){
      const {Universe}=await import('./universe.js');
      universe=new Universe($('#universe'),$('#universe-tooltip'),id=>{
        const r=matching.find(r=>r.id===id),panel=$('#universe-selection');panel.hidden=!r;
        if(r)panel.innerHTML='<strong>'+esc(r.id)+'</strong><p>'+esc(r.title)+'</p><button type="button" data-record="'+esc(r.id)+'">Open evidence</button>';
      },paused=>$('#site-motion').textContent=paused?'Resume motion':'Pause motion',status=>{
        const p=rendererPresentation(status);$('#renderer-state').textContent=p.label;$('#renderer-notice').textContent=p.notice;$('#renderer-notice').hidden=!p.notice;$('#site-quality').value=status.quality||'canvas';
      });
    }
    universe.setRecords(matching);universe.setVisible(true);
  }catch{$('#renderer-state').textContent='Graphics unavailable. Use the records table.';}
});
$('#site-quality').addEventListener('change',event=>universe?.setQuality(event.target.value));
$('#site-motion').addEventListener('click',()=>{const paused=universe?.toggle();$('#site-motion').textContent=paused?'Resume motion':'Pause motion';});
$('#site-reset').addEventListener('click',()=>universe?.reset());
document.addEventListener('visibilitychange',()=>universe?.setVisible(!document.hidden));
try{
  const response=await fetch('./snapshot.json',{cache:'no-cache'});if(!response.ok)throw new Error('The snapshot could not be downloaded.');
  snapshot=await response.json();
  $('#snapshot-status').textContent='Published '+date(snapshot.exportedAt,true)+' · '+num(snapshot.exportedRecords)+' exported records from '+num(snapshot.totalCollected)+' collected records. New observations appear when this site is republished.';
  $('#site-export-time').textContent='Last collection: '+date(snapshot.lastSuccess,true);
  $('#site-sources').innerHTML=snapshot.sources.map(s=>'<div class="list-row"><div><strong>'+esc(sourceNames[s.id]||s.id)+'</strong><p>'+esc(s.message||'')+'</p></div><span class="muted">'+date(s.lastSuccess,true)+'</span></div>').join('');
  render();
}catch(error){$('#snapshot-status').textContent=error.message;$('#site-results').innerHTML=empty('Catalog unavailable','Try again after the next successful publication.');}
