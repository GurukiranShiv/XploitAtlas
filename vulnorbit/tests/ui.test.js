import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
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
test('the interface and setup guide use the approved XploitAtlas branding',()=>{
  const html=readFileSync(new URL('../static/index.html',import.meta.url),'utf8');
  const readme=readFileSync(new URL('../README.md',import.meta.url),'utf8');
  const wording='Helping you understand vulnerabilities, why they matter, and what to prioritize.';
  assert.ok(html.includes('<title>XploitAtlas — Vulnerability intelligence</title>'));
  assert.ok(html.includes('aria-label="XploitAtlas home"'));
  assert.ok(html.includes('Xploit<span class="accent">Atlas</span>'));
  assert.ok(html.includes('<h1>Xploit<span>Atlas</span></h1>'));
  assert.ok(html.includes(wording));
  assert.ok(readme.startsWith('# XploitAtlas\n'));
  assert.ok(readme.includes(wording));
  assert.ok(!html.includes('VulnOrbit'));
});
