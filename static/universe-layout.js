/* Positions are reproducible visual layout, never telemetry or a risk metric. */
export function hash(text) {
  let value=2166136261;
  for(let i=0;i<text.length;i++)value=Math.imul(value^text.charCodeAt(i),16777619);
  return value>>>0;
}
const unit=key=>hash(String(key))/4294967296;

export function groupPosition(group) {
  const angle=unit('group:'+group)*Math.PI*2;
  const elevation=(unit('elevation:'+group)-.5)*2.2;
  const radius=175+unit('radius:'+group)*100;
  return {x:Math.cos(angle)*Math.cos(elevation)*radius,
    y:Math.sin(elevation)*radius,z:Math.sin(angle)*Math.cos(elevation)*radius};
}

export function positionFor(identity,group) {
  const center=groupPosition(group);
  const theta=unit('theta:'+identity)*Math.PI*2;
  const phi=Math.acos(2*unit('phi:'+identity)-1);
  // A fixed, identity-derived spread keeps positions stable across filters/imports.
  const spread=34+unit('group-spread:'+group)*26;
  const r=spread*Math.cbrt(unit('spread:'+identity));
  return {x:center.x+r*Math.sin(phi)*Math.cos(theta),
    y:center.y+r*Math.cos(phi),z:center.z+r*Math.sin(phi)*Math.sin(theta),center};
}

export function groupFor(record,grouping='vendor') {
  if(grouping==='weakness') {
    const weakness=(record.weaknesses||[])[0];
    if(weakness?.id)return weakness.id;
    return record.cwes?.[0]||'Weakness not classified';
  }
  if(grouping==='severity')return record.severity||'Unknown';
  if(grouping==='source') {
    const values=[...(record.sourceIds||[])].sort();
    return values.length?values.map(value=>value.toUpperCase()).join(' + '):'Source unavailable';
  }
  return record.clusterLabel||record.vendor||'Unspecified vendor';
}

export function layoutRecords(records,grouping='vendor') {
  const labels=new Map();
  if(grouping==='weakness')for(const record of records){const weakness=(record.weaknesses||[])[0];if(weakness?.name)labels.set(weakness.id,weakness.id+' · '+weakness.name);}
  return records.map(record=>{
    const group=groupFor(record,grouping);
    return {record,vendor:labels.get(group)||group,group,...positionFor(record.id,group)};
  });
}

export function colorFor(record) {
  if(record.severity==='Critical')return '#ff4fd8';
  if(record.severity==='High')return '#ffc857';
  if(record.severity==='Medium')return '#39c9ff';
  if(record.severity==='Low')return '#2fe4a7';
  if(record.severity==='None')return '#d8f5ff';
  return '#71809f';
}

export function radiusFor(record) {
  return typeof record.cvss==='number'&&Number.isFinite(record.cvss)
    ?1.25+Math.max(0,Math.min(10,record.cvss))*.24:1.65;
}

export function visualSignature(records,grouping='vendor') {
  return grouping+'|'+JSON.stringify(records.map(r=>[r.id,groupFor(r,grouping),grouping==='weakness'?r.weaknesses:null,r.cvss,r.severity,r.epss,!!r.kev,!!r.withdrawn,(r.sourceIds||[]).join(',')]));
}

export function recentEventIds(events,at=Date.now()) {
  const ids=new Set();
  for(const event of events||[]) {
    const stamp=Date.parse(event.observedAt);
    if(typeof event.cve==='string'&&Number.isFinite(stamp)&&stamp<=at&&stamp>=at-15*60*1000)ids.add(event.cve);
  }
  return ids;
}
