import test from 'node:test';
import assert from 'node:assert/strict';
import {escapeHTML,link,metric,percent,recordTable} from '../static/ui.js';
import {layoutRecords} from '../static/universe.js';
test('source text cannot become HTML',()=>{
  const value='<img src=x onerror="alert(1)">';
  assert.equal(escapeHTML(value),'&lt;img src=x onerror=&quot;alert(1)&quot;&gt;');
  assert.ok(!link('javascript:alert(1)','Open').includes('<a'));
  assert.ok(!link('https://name:secret@example.com','Open').includes('<a'));
  assert.ok(link('https://www.cve.org/','<source>').includes('&lt;source&gt;'));
});
test('missing metrics stay unknown and zero remains zero',()=>{
  assert.equal(metric(null),'Unknown');
  assert.equal(metric(undefined),'Unknown');
  assert.equal(percent(null),'Unknown');
  assert.equal(metric(0),'0.0');
  assert.equal(percent(0),'0.00%');
});
test('an empty catalog cannot generate visual records',()=>{
  assert.deepEqual(layoutRecords([]),[]);
  assert.ok(recordTable([]).includes('No matching observations'));
});
