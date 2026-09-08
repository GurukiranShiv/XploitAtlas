const CACHE_NAME='mastermonk-shell-3.2.0';
const SHELL=[
  '/',
  '/static/index.html',
  '/static/style.css',
  '/static/app.js',
  '/static/briefing.js',
  '/static/cosmos.css',
  '/static/space-geometry.js',
  '/static/ui.js',
  '/static/osint.js',
  '/static/evidence-graph.js',
  '/static/renderer-status.js',
  '/static/universe.js',
  '/static/universe-layout.js',
  '/static/universe-canvas.js',
  '/static/universe-webgl.js',
  '/static/vendor/three.js',
  '/static/media/mastermonk-logo.png',
  '/static/media/deep-field.webp',
  '/static/icons/favicon-64.png',
  '/static/icons/mastermonk-192.png',
  '/static/icons/mastermonk-512.png',
  '/static/fonts/IBMPlexMono-Regular.woff2',
  '/static/fonts/IBMPlexSans-Regular.woff2',
  '/static/fonts/IBMPlexSans-SemiBold.woff2',
  '/static/fonts/IBMPlexSerif-Medium.woff2',
  '/static/fonts/IBMPlexSerif-Regular.woff2',
  '/manifest.webmanifest'
];

self.addEventListener('install',event=>{
  event.waitUntil(caches.open(CACHE_NAME).then(cache=>cache.addAll(SHELL)).then(()=>self.skipWaiting()));
});

self.addEventListener('activate',event=>{
  event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(key=>key.startsWith('mastermonk-shell-')&&key!==CACHE_NAME).map(key=>caches.delete(key)))).then(()=>self.clients.claim()));
});

self.addEventListener('fetch',event=>{
  const request=event.request;
  if(request.method!=='GET')return;
  const url=new URL(request.url);
  if(url.origin!==self.location.origin)return;

  // Intelligence, account, feed and record responses always come from the server.
  // The PWA never stores vulnerability data or authenticated responses.
  if(url.pathname.startsWith('/api/')||url.pathname.startsWith('/feeds/')||url.pathname.startsWith('/vulnerability/')||url.pathname.startsWith('/sitemaps/'))return;

  if(request.mode==='navigate'){
    event.respondWith(fetch(request).catch(()=>caches.match('/')));
    return;
  }

  if(url.pathname.startsWith('/static/')||url.pathname==='/manifest.webmanifest'){
    event.respondWith(caches.match(request).then(cached=>cached||fetch(request)));
  }
});
