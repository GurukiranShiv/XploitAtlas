import {build} from 'esbuild';
import {mkdir, readFile, writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const root=fileURLToPath(new URL('../',import.meta.url));
await mkdir(new URL('../static/vendor/',import.meta.url),{recursive:true});
await build({
  absWorkingDir:root,entryPoints:['tools/three-entry.js'],
  outfile:'static/vendor/three.js',bundle:true,format:'esm',platform:'browser',
  target:['es2022'],minify:true,legalComments:'none',
  banner:{js:'/*! Three.js r180 (MIT) — locally bundled for MasterMonk. See THREE-LICENSE.md. */'},
});
const license=await readFile(new URL('../node_modules/three/LICENSE',import.meta.url),'utf8');
await writeFile(new URL('../static/vendor/THREE-LICENSE.md',import.meta.url),license);
const bytes=await readFile(new URL('../static/vendor/three.js',import.meta.url));
const digest=createHash('sha256').update(bytes).digest('hex');
await writeFile(new URL('../static/vendor/BUILD.json',import.meta.url),JSON.stringify({
  library:'three',version:'0.180.0',bundler:'esbuild 0.25.10',
  source:'https://github.com/mrdoob/three.js/tree/r180',
  license:'MIT',file:'three.js',bytes:bytes.length,sha256:digest,
  rebuild:'npm ci --ignore-scripts && npm run build:vendor'
},null,2)+'\n');
console.log('Local Three.js bundle:',bytes.length,'bytes; SHA-256',digest);
