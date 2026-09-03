import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {icon} from '../static/ui.js';

const css=readFileSync(new URL('../static/style.css',import.meta.url),'utf8');
const html=readFileSync(new URL('../static/index.html',import.meta.url),'utf8');
function rule(selector){
  const start=css.indexOf(selector+'{');
  assert.notEqual(start,-1,'Missing rule: '+selector);
  return css.slice(start+selector.length+1,css.indexOf('}',start));
}
function value(selector,property){
  return rule(selector).match(new RegExp('(?:^|;)\\s*'+property+'\\s*:\\s*([^;}]+)'))?.[1]?.trim();
}

test('all shared icons keep intrinsic dimensions without relying on their parent',()=>{
  for(const name of ['clock','refresh','nodes','shield','package','target','code','plus','minus','pause','play','expand','download','reset','search','arrow','fingerprint','wrench','close','external','check','alert','copy','orbit','list','spark','unknown']){
    const svg=icon(name);
    assert.match(svg,/<svg class="ui-icon" width="18" height="18" /);
    assert.match(svg,/aria-hidden="true" focusable="false"/);
    assert.ok(!svg.includes('width="100%"'));
  }
  assert.equal(value('svg.ui-icon','width'),'18px');
  assert.equal(value('svg.ui-icon','height'),'18px');
  assert.equal(value('svg.ui-icon','flex'),'0 0 18px');
});
test('the scheduler gives the icon its own bounded column and permits text wrapping',()=>{
  assert.equal(value('.history-note','display'),'grid');
  assert.equal(value('.history-note','grid-template-columns'),'18px minmax(0,1fr)');
  assert.equal(value('.history-note p','min-width'),'0');
  assert.equal(value('.history-note p','overflow-wrap'),'anywhere');
  assert.equal(value('.history-note p','white-space'),'normal');
  const guard=rule('.history-note>svg,.history-note [data-icon],.history-note svg.ui-icon');
  assert.match(guard,/max-width:18px/);
  assert.match(guard,/max-height:18px/);
  assert.match(html,/id="scheduler-status" class="history-note" role="status"/);
});
test('the exact local fonts and their license are present',()=>{
  const expected={
    'IBMPlexSans-Regular.woff2':'231a1ad716215de37ce8102dde533be859036f91',
    'IBMPlexSans-SemiBold.woff2':'b96a19c2457d296f597169ea104c5c1ab1435a46',
    'IBMPlexSerif-Regular.woff2':'4762ee96e4b681a07b5e0d43ab7cf79f439f9b0e',
    'IBMPlexSerif-Medium.woff2':'65f03e761f8512bc274b3f9d5b73a11de7eeb4b0',
    'IBMPlexMono-Regular.woff2':'8bdb4c4b3f8fae88cc2e3c9c744952dccf89b15a'
  };
  for(const [name,sha] of Object.entries(expected)){
    const bytes=readFileSync(new URL('../static/fonts/'+name,import.meta.url));
    assert.equal(bytes.subarray(0,4).toString(),'wOF2');
    assert.equal(createHash('sha1').update(Buffer.from('blob '+bytes.length+'\0')).update(bytes).digest('hex'),sha);
    assert.ok(css.includes('url("./fonts/'+name+'")'));
  }
  assert.match(readFileSync(new URL('../static/fonts/OFL.txt',import.meta.url),'utf8'),/SIL OPEN FONT LICENSE/);
  assert.equal((css.match(/@font-face/g)||[]).length,5);
  assert.ok(!/fonts\.googleapis|fonts\.gstatic|https?:\/\/[^)\s]+\.woff/.test(css+html));
});
test('font and stylesheet references resolve to bundled files',()=>{
  for(const match of css.matchAll(/url\(["']?([^"')]+)["']?\)/g)){
    assert.ok(!/^(https?:|data:)/.test(match[1]));
    assert.ok(readFileSync(new URL(match[1],new URL('../static/style.css',import.meta.url))).length>0);
  }
  assert.match(html,/style\.css\?v=atlas-1/);
  assert.match(html,/app\.js\?v=atlas-1/);
});
test('the atlas palette and typography replace the previous neon theme',()=>{
  assert.equal(value(':root','--bg'),'#f5f4ee');
  assert.equal(value(':root','--accent'),'#93462b');
  assert.equal(value(':root','--ink'),'#163047');
  assert.match(rule(':root'),/--display:"IBM Plex Serif"/);
  assert.match(rule(':root'),/--font:"IBM Plex Sans"/);
  assert.ok(!css.includes('#c5f36b'));
  assert.ok(!css.includes('--font:Inter'));
});
function luminance(hex){
  const c=hex.replace('#','').match(/../g).map(s=>parseInt(s,16)/255).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4);
  return .2126*c[0]+.7152*c[1]+.0722*c[2];
}
function contrast(a,b){
  const [lo,hi]=[luminance(a),luminance(b)].sort((x,y)=>x-y);
  return (hi+.05)/(lo+.05);
}
test('primary text and the core action colors have readable contrast',()=>{
  const bg=value(':root','--bg');
  for(const name of ['--text','--muted','--faint','--accent','--coral','--purple','--amber','--blue']){
    assert.ok(contrast(value(':root',name),bg)>=4.5,name+' on page background');
  }
  assert.ok(contrast('#fffefa',value(':root','--accent'))>=4.5);
  assert.ok(contrast('#c4d2df','#163047')>=4.5);
  assert.ok(contrast('#b0c1d1','#0e2033')>=4.5);
});
test('narrow layouts retain scroll containers and wrapping rules',()=>{
  assert.equal(value('.table-scroll','overflow-x'),'auto');
  assert.match(css,/@media\(max-width:1200px\)/);
  assert.match(css,/@media\(max-width:720px\)/);
  assert.match(css,/@media\(max-width:420px\)/);
  assert.match(css,/\.package-layout,\.learning-layout,\.method-grid,\.sources-grid\{grid-template-columns:minmax\(0,1fr\)/);
  assert.ok(!/body\{[^}]*overflow-x:hidden/.test(css),'Do not hide the bug by clipping the whole page');
});
test('reduced-motion and keyboard-focus treatments remain available',()=>{
  assert.match(css,/@media\(prefers-reduced-motion:reduce\)/);
  assert.match(css,/animation:none!important;transition:none!important/);
  assert.ok(css.includes('canvas:focus-visible'));
  assert.ok(css.includes('summary:focus-visible'));
});
