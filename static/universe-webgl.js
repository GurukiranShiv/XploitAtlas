/* GPU-rendered geometry for real catalog records. No generated intelligence. */
import * as T from './vendor/three.js';
import {layoutRecords,colorFor,radiusFor,visualSignature,recentEventIds} from './universe-layout.js';
import {escapeHTML as esc,metric,percent} from './ui.js';
import {crystal,cloudPlane,cloudMaterial} from './space-geometry.js';

const HOME_DISTANCE=1050;
const HOME_DIRECTION=new T.Vector3(.62,.29,.82).normalize();
const SOURCE_COLORS={cisa:'#ff3c62',nvd:'#39c9ff',github:'#a887ff',epss:'#2fe4a7',cve:'#ffc857',osv:'#ff7abf'};

export class WebGLUniverse {
  constructor(canvas,tooltip,onSelect,onMotion,options={}) {
    this.mode='webgl';
    this.canvas=canvas;this.stage=canvas.closest('.universe-stage');this.tooltip=tooltip;this.onSelect=onSelect;this.onMotion=onMotion;
    this.options=options;this.labelsElement=options.labelsElement;this.minimap=options.minimap;this.axisElement=options.axisElement;
    this.nodes=[];this.nodeMap=new Map();this.selected=null;this.hover=null;this.visible=true;
    this.dirty=true;this.disposed=false;this.elapsed=0;this.events=[];this.highlightIds=new Set();
    this.nodeMeshes=[];this.newTrails=[];this.announcedNew=new Set();this.grouping='vendor';this.firstFlight=true;
    this.labels=[];this.abort=new AbortController();this.pointer=new T.Vector2();this.drag=null;this.activePointers=new Set();
    this.reduced=window.matchMedia('(prefers-reduced-motion: reduce)');
    this.paused=this.reduced.matches;this.quality=options.quality||'balanced';
    try {this.setup();}catch(error){this.dispose();throw error;}
  }
  setup() {
    this.renderer=new T.WebGLRenderer({canvas:this.canvas,alpha:true,antialias:true,powerPreference:'default'});
    this.ctx=this.renderer.getContext();
    this.renderer.outputColorSpace=T.SRGBColorSpace;
    this.renderer.toneMapping=T.ACESFilmicToneMapping;this.renderer.toneMappingExposure=1.1;
    this.renderer.setClearColor(0x03030a,1);
    this.scene=new T.Scene();this.scene.fog=new T.FogExp2(0x03030a,.00048);
    this.camera=new T.PerspectiveCamera(43,1,1,5000);
    this.camera.position.copy(HOME_DIRECTION).multiplyScalar(HOME_DISTANCE);
    this.scene.add(new T.AmbientLight('#899cff',1.28));
    const key=new T.DirectionalLight('#f5ffff',2.15);key.position.set(250,500,550);this.scene.add(key);
    const rim=new T.DirectionalLight('#24e5d5',1.05);rim.position.set(-500,100,-200);this.scene.add(rim);
    this.controls=new T.OrbitControls(this.camera,this.canvas);
    this.controls.enableDamping=true;this.controls.dampingFactor=.085;
    this.controls.minDistance=35;this.controls.maxDistance=2200;
    this.controls.autoRotateSpeed=.34;this.controls.rotateSpeed=.65;
    this.controls.zoomSpeed=.8;this.controls.panSpeed=.55;
    this.controls.minPolarAngle=.08;this.controls.maxPolarAngle=Math.PI-.08;
    this.raycaster=new T.Raycaster();
    this.nodeGeometries={Critical:crystal(5,1.35,.92),High:crystal(6,.95,1),
      Medium:crystal(4,1.1,.9),Low:crystal(3,1,.8),None:new T.SphereGeometry(1,10,7),Unknown:crystal(3,.65,.85)};
    this.haloGeometry=new T.SphereGeometry(1,12,8);
    this.nodeMaterial=new T.MeshStandardMaterial({roughness:.29,metalness:.19,emissive:'#101533',emissiveIntensity:.34});
    this.glowMaterial=new T.MeshBasicMaterial({transparent:true,opacity:.1,depthWrite:false});
    this.coronaMaterial=new T.MeshBasicMaterial({transparent:true,opacity:.16,wireframe:true,depthWrite:false});
    this.eventGeometry=new T.SphereGeometry(1,10,7);
    this.eventMaterial=new T.MeshBasicMaterial({color:'#39e6ff',wireframe:true,transparent:true,opacity:.31,depthWrite:false});
    this.kevGeometry=new T.TorusGeometry(.94,.07,6,24);
    this.kevMaterial=new T.MeshBasicMaterial({color:'#ff3c62',transparent:true,opacity:.88,depthWrite:false});
    this.sourceGeometry=new T.SphereGeometry(1,10,7);this.sourceSatellites=[];
    this.selectionRing=new T.Mesh(new T.TorusGeometry(1,.035,6,56),new T.MeshBasicMaterial({color:'#c8fbff',transparent:true,opacity:.96,depthWrite:false}));
    this.selectionRing.visible=false;this.scene.add(this.selectionRing);
    this.buildDeepSpace();
    this.guides=[];
    for(const tilt of [0,Math.PI/2,-.65]) {
      const points=[];
      for(let i=0;i<144;i++){const a=i/144*Math.PI*2;points.push(new T.Vector3(Math.cos(a)*350,Math.sin(a)*350*Math.sin(tilt),Math.sin(a)*350*Math.cos(tilt)));}
      const ring=new T.LineLoop(new T.BufferGeometry().setFromPoints(points),new T.LineBasicMaterial({color:'#5264a7',transparent:true,opacity:.15,depthWrite:false}));
      ring.visible=false;this.scene.add(ring);this.guides.push(ring);
    }
    this.setQuality(this.quality);
    this.motionHandler=event=>{if(event.matches)this.setPaused(true);this.dirty=true;};
    this.reduced.addEventListener('change',this.motionHandler);
    this.resizeObserver=new ResizeObserver(()=>this.resize());this.resizeObserver.observe(this.canvas);
    this.bind();this.resize();
    this.renderer.setAnimationLoop(time=>{
      try{this.frame(time);}catch{this.renderer.setAnimationLoop(null);queueMicrotask(()=>{if(!this.disposed)this.options.onRenderError?.();});}
    });
  }
  listen(target,type,handler,options={}) {target.addEventListener(type,handler,{...options,signal:this.abort.signal});}
  buildDeepSpace() {
    // These seeded particles and clouds are navigation scenery, never vulnerability or attack observations.
    let seed=0x4d4d3101;
    const random=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed/4294967296;};
    this.starGeometry=new T.SphereGeometry(1,4,3);
    this.starMaterial=new T.MeshBasicMaterial({color:'#eef3ff',transparent:true,opacity:.52,depthWrite:false});
    this.starfield=new T.InstancedMesh(this.starGeometry,this.starMaterial,750);
    const matrix=new T.Matrix4(),rotation=new T.Quaternion();
    for(let i=0;i<750;i++){
      const radius=650+random()*1500,theta=random()*Math.PI*2,phi=Math.acos(2*random()-1);
      const position=new T.Vector3(radius*Math.sin(phi)*Math.cos(theta),radius*Math.cos(phi),radius*Math.sin(phi)*Math.sin(theta)),size=.25+random()*.85;
      matrix.compose(position,rotation,new T.Vector3(size,size,size));this.starfield.setMatrixAt(i,matrix);
    }
    this.starfield.instanceMatrix.needsUpdate=true;this.starfield.computeBoundingSphere();this.scene.add(this.starfield);
    this.cloudGeometry=cloudPlane();this.clouds=[];this.flightClouds=[];
    // Scenery stays neutral so evidence colors remain unmistakable.
    const colors=['#24364c','#34465a','#536173','#788391'];
    for(let i=0;i<34;i++){
      const material=cloudMaterial(colors[i%colors.length],.12+random()*.09);
      const sprite=new T.Mesh(this.cloudGeometry,material),radius=120+random()*610,theta=random()*Math.PI*2,phi=Math.acos(2*random()-1);
      sprite.position.set(radius*Math.sin(phi)*Math.cos(theta),radius*Math.cos(phi)*.7,radius*Math.sin(phi)*Math.sin(theta));
      const size=150+random()*330;sprite.scale.set(size,size*(.45+random()*.5),1);sprite.userData.baseOpacity=material.opacity;
      this.scene.add(sprite);this.clouds.push(sprite);
    }
  }
  bind() {
    this.controls.addEventListener('start',()=>{this.cancelFlight(true);this.tooltip.hidden=true;});
    this.controls.addEventListener('change',()=>{this.dirty=true;});
    this.listen(this.canvas,'pointerdown',event=>{
      this.activePointers.add(event.pointerId);
      if(this.activePointers.size>1){if(this.drag)this.drag.moved=true;this.pendingPointer=null;return;}
      if(event.button!==0)return;
      this.canvas.focus({preventScroll:true});
      this.drag={id:event.pointerId,x:event.clientX,y:event.clientY,moved:false};
      this.tooltip.hidden=true;
    });
    this.listen(this.canvas,'pointermove',event=>{
      if(this.drag){const threshold=event.pointerType==='touch'?12:5;if(Math.hypot(event.clientX-this.drag.x,event.clientY-this.drag.y)>threshold)this.drag.moved=true;return;}
      this.pendingPointer={x:event.clientX,y:event.clientY};
    });
    this.listen(this.canvas,'pointerup',event=>{
      this.activePointers.delete(event.pointerId);
      if(this.drag?.id!==event.pointerId)return;
      const drag=this.drag;this.drag=null;
      if(drag.moved||this.activePointers.size)return;
      const node=this.pick(event.clientX,event.clientY,event.pointerType==='touch'?22:9);
      if(node)this.focus(node.record.id,true,()=>this.onSelect(node.record.id));
    });
    this.listen(this.canvas,'pointercancel',event=>{this.activePointers.delete(event.pointerId);this.drag=null;this.clearHover();});
    this.listen(this.canvas,'pointerleave',()=>{this.pendingPointer=null;this.clearHover();});
    this.listen(this.canvas,'keydown',event=>{
      const spherical=new T.Spherical().setFromVector3(this.camera.position.clone().sub(this.controls.target));
      if(event.key==='ArrowLeft')spherical.theta-=.11;
      else if(event.key==='ArrowRight')spherical.theta+=.11;
      else if(event.key==='ArrowUp')spherical.phi=Math.max(.08,spherical.phi-.09);
      else if(event.key==='ArrowDown')spherical.phi=Math.min(Math.PI-.08,spherical.phi+.09);
      else if(event.key==='+'||event.key==='='){this.setZoom(this.zoom*1.2);event.preventDefault();return;}
      else if(event.key==='-'){this.setZoom(this.zoom/1.2);event.preventDefault();return;}
      else if(event.key==='Home'){this.reset();event.preventDefault();return;}
      else if(event.key===' '){this.toggle();event.preventDefault();return;}
      else return;
      event.preventDefault();this.cancelFlight(true);
      this.camera.position.setFromSpherical(spherical).add(this.controls.target);this.controls.update();this.clearHover();this.dirty=true;
    });
    this.listen(this.canvas,'webglcontextlost',event=>{event.preventDefault();queueMicrotask(()=>{if(!this.disposed)this.options.onContextLost?.();});});
  }
  setQuality(quality) {
    this.quality=['balanced','low','cinematic'].includes(quality)?quality:'balanced';
    this.disposeComposer();
    if(this.quality!=='low'&&!this.renderer.extensions.has('EXT_color_buffer_float'))this.quality='low';
    if(this.quality!=='low') {
      try {
        this.composer=new T.EffectComposer(this.renderer);
        this.composer.addPass(new T.RenderPass(this.scene,this.camera));
        this.bloom=new T.UnrealBloomPass(new T.Vector2(1,1),this.quality==='cinematic'?1.18:.42,this.quality==='cinematic'?.82:.48,this.quality==='cinematic'?.32:.55);
        this.outputPass=new T.OutputPass();
        this.composer.addPass(this.bloom);this.composer.addPass(this.outputPass);
      }catch {this.disposeComposer();this.quality='low';}
    }
    this.applyQualityAppearance();
    if(this.nodes.length){this.buildCoronas();this.buildGlow();this.buildEventRings();this.updateColors();}
    this.resize();this.dirty=true;
  }
  applyQualityAppearance() {
    const profile={
      low:{background:'#02050f',fog:.00014,fov:54,exposure:.82,roughness:.88,metalness:.01,emissive:.03,corona:0,glow:0,event:.12,guide:0,rotate:.16,cloud:0,stars:.3,size:1},
      balanced:{background:'#030712',fog:.00034,fov:44,exposure:1.12,roughness:.38,metalness:.15,emissive:.38,corona:.16,glow:.075,event:.3,guide:.1,rotate:.31,cloud:.62,stars:.46,size:1.35},
      cinematic:{background:'#050817',fog:.00054,fov:37,exposure:1.38,roughness:.18,metalness:.3,emissive:.84,corona:.27,glow:.16,event:.48,guide:.2,rotate:.44,cloud:.88,stars:.62,size:1.85}
    }[this.quality];
    this.renderer.setClearColor(profile.background,this.quality==='low'?1:0);this.renderer.toneMappingExposure=profile.exposure;
    this.scene.fog.color.set(profile.background);this.scene.fog.density=profile.fog;
    this.camera.fov=profile.fov;this.camera.updateProjectionMatrix();this.controls.autoRotateSpeed=profile.rotate;
    this.nodeMaterial.roughness=profile.roughness;this.nodeMaterial.metalness=profile.metalness;this.nodeMaterial.emissiveIntensity=profile.emissive;this.nodeMaterial.needsUpdate=true;
    this.coronaMaterial.opacity=profile.corona;this.glowMaterial.opacity=profile.glow;this.eventMaterial.opacity=profile.event;
    for(const guide of this.guides){guide.material.opacity=profile.guide;guide.visible=this.quality!=='low'&&!!this.nodes.length;}
    if(this.coronaMesh)this.coronaMesh.visible=this.quality!=='low';
    if(this.glowMesh)this.glowMesh.visible=this.quality!=='low';
    if(this.eventMesh)this.eventMesh.visible=this.quality!=='low';
    for(const cloud of this.clouds||[]){cloud.visible=profile.cloud>0;cloud.material.opacity=cloud.userData.baseOpacity*profile.cloud;}
    if(this.starMaterial)this.starMaterial.opacity=profile.stars;
    if(this.stage)this.stage.dataset.renderProfile=this.quality;
  }
  disposeComposer() {
    this.bloom?.dispose();this.outputPass?.dispose();this.composer?.dispose();
    this.bloom=null;this.outputPass=null;this.composer=null;
  }
  resize() {
    if(!this.renderer||this.disposed)return;
    const rect=this.canvas.getBoundingClientRect();if(!rect.width||!rect.height)return;
    this.width=rect.width;this.height=rect.height;
    const cap=this.quality==='cinematic'?1.75:this.quality==='balanced'?1.25:1;
    const ratio=Math.min(window.devicePixelRatio||1,cap);
    this.renderer.setPixelRatio(ratio);this.renderer.setSize(this.width,this.height,false);
    this.composer?.setPixelRatio(ratio);this.composer?.setSize(this.width,this.height);
    this.camera.aspect=this.width/this.height;this.camera.updateProjectionMatrix();this.dirty=true;
  }
  setRecords(records,grouping='vendor') {
    const signature=visualSignature(records,grouping);this.grouping=grouping;
    if(signature===this.signature) {
      const current=new Map(records.map(r=>[r.id,r]));
      for(const node of this.nodes)node.record=current.get(node.record.id);
      this.clearHover();this.dirty=true;return;
    }
    this.signature=signature;this.nodes=layoutRecords(records,grouping);this.nodeMap=new Map(this.nodes.map(n=>[n.record.id,n]));
    this.clearHover();
    for(const mesh of this.nodeMeshes){this.scene.remove(mesh);mesh.dispose();}this.nodeMeshes=[];
    if(this.coronaMesh){this.scene.remove(this.coronaMesh);this.coronaMesh.dispose();this.coronaMesh=null;}
    if(this.glowMesh){this.scene.remove(this.glowMesh);this.glowMesh.dispose();this.glowMesh=null;}
    if(this.nodes.length) {
      const buckets=new Map();
      for(const node of this.nodes){const key=this.nodeGeometries[node.record.severity]?node.record.severity:'Unknown';if(!buckets.has(key))buckets.set(key,[]);buckets.get(key).push(node);}
      for(const [severity,nodes] of buckets){
        const mesh=new T.InstancedMesh(this.nodeGeometries[severity],this.nodeMaterial,nodes.length),matrix=new T.Matrix4();
        mesh.userData.nodes=nodes;
        nodes.forEach((node,index)=>{
          const radius=radiusFor(node.record),shape={Critical:[1.28,.92,1.28],High:[1.12,1.12,1.12],Medium:[1,1.25,1],Low:[.92,1.35,.92],None:[.78,.78,.78],Unknown:[.82,.82,.82]}[severity];
          const rotation=new T.Quaternion().setFromAxisAngle(new T.Vector3(.3,1,.2).normalize(),index*.37);
          matrix.compose(new T.Vector3(node.x,node.y,node.z),rotation,new T.Vector3(radius*shape[0],radius*shape[1],radius*shape[2]));
          mesh.setMatrixAt(index,matrix);
        });
        mesh.instanceMatrix.needsUpdate=true;mesh.computeBoundingSphere();this.scene.add(mesh);this.nodeMeshes.push(mesh);
      }
    }
    for(const guide of this.guides)guide.visible=!!this.nodes.length&&this.quality!=='low';
    if(!this.nodeMap.has(this.selected))this.selected=null;
    this.buildCoronas();this.buildGlow();this.buildKevMarkers();this.updateColors();this.updateSelection();this.buildLabels();this.buildEventRings();this.dirty=true;
  }
  buildCoronas() {
    if(this.coronaMesh){this.scene.remove(this.coronaMesh);this.coronaMesh.dispose();this.coronaMesh=null;}
    const threshold=this.quality==='low'?Infinity:this.quality==='balanced'?.05:0;
    this.coronaNodes=this.nodes.filter(node=>typeof node.record.epss==='number'&&Number.isFinite(node.record.epss)&&node.record.epss>=threshold);
    if(!this.coronaNodes.length)return;
    this.coronaMesh=new T.InstancedMesh(this.haloGeometry,this.coronaMaterial,this.coronaNodes.length);
    const matrix=new T.Matrix4(),rotation=new T.Quaternion();
    this.coronaNodes.forEach((node,index)=>{
      const score=Math.max(0,Math.min(1,node.record.epss)),radius=radiusFor(node.record)+1.1+Math.sqrt(score)*5;
      matrix.compose(new T.Vector3(node.x,node.y,node.z),rotation,new T.Vector3(radius,radius,radius));
      this.coronaMesh.setMatrixAt(index,matrix);
    });
    this.coronaMesh.instanceMatrix.needsUpdate=true;this.coronaMesh.computeBoundingSphere();this.scene.add(this.coronaMesh);
  }
  buildGlow() {
    if(this.glowMesh){this.scene.remove(this.glowMesh);this.glowMesh.dispose();this.glowMesh=null;}
    this.glowNodes=this.quality==='low'?[]:this.quality==='cinematic'?this.nodes:this.nodes.filter(node=>node.record.kev||node.record.severity==='Critical'||(typeof node.record.epss==='number'&&node.record.epss>=.1));
    if(!this.glowNodes.length)return;
    this.glowMesh=new T.InstancedMesh(this.haloGeometry,this.glowMaterial,this.glowNodes.length);
    const matrix=new T.Matrix4(),rotation=new T.Quaternion(),extra=this.quality==='cinematic'?3.2:1.35;
    this.glowNodes.forEach((node,index)=>{
      const radius=radiusFor(node.record)+extra;
      matrix.compose(new T.Vector3(node.x,node.y,node.z),rotation,new T.Vector3(radius,radius,radius));
      this.glowMesh.setMatrixAt(index,matrix);
    });
    this.glowMesh.instanceMatrix.needsUpdate=true;this.glowMesh.computeBoundingSphere();this.scene.add(this.glowMesh);
  }
  updateColors() {
    if(!this.nodeMeshes.length)return;
    const selected=this.nodeMap.get(this.selected);
    for(const mesh of this.nodeMeshes){
      mesh.userData.nodes.forEach((node,index)=>{
        const color=new T.Color(colorFor(node.record));
        if(selected&&node.vendor!==selected.vendor)color.multiplyScalar(.1);
        else if(selected&&node.record.id!==selected.record.id)color.multiplyScalar(.52);
        mesh.setColorAt(index,color);
      });
      mesh.instanceColor.needsUpdate=true;
    }
    if(this.coronaMesh){
      this.coronaNodes.forEach((node,index)=>{const color=new T.Color(colorFor(node.record));if(selected&&node.vendor!==selected.vendor)color.multiplyScalar(.12);else color.multiplyScalar(.75);this.coronaMesh.setColorAt(index,color);});
      this.coronaMesh.instanceColor.needsUpdate=true;
    }
    if(this.glowMesh){
      this.glowNodes.forEach((node,index)=>{const color=new T.Color(colorFor(node.record));if(selected&&node.vendor!==selected.vendor)color.multiplyScalar(.08);else color.multiplyScalar(this.quality==='cinematic'?.9:.56);this.glowMesh.setColorAt(index,color);});
      this.glowMesh.instanceColor.needsUpdate=true;
    }
    if(this.kevMesh){
      this.kevNodes.forEach((node,index)=>this.kevMesh.setColorAt(index,new T.Color(selected&&node.vendor!==selected.vendor?'#383838':'#ffffff')));
      this.kevMesh.instanceColor.needsUpdate=true;
    }
  }
  buildKevMarkers(){
    if(this.kevMesh){this.scene.remove(this.kevMesh);this.kevMesh.dispose();this.kevMesh=null;}
    this.kevNodes=this.nodes.filter(node=>node.record.kev);
    if(!this.kevNodes.length)return;
    this.kevMesh=new T.InstancedMesh(this.kevGeometry,this.kevMaterial,this.kevNodes.length);
    this.scene.add(this.kevMesh);this.updateKevMarkers();this.kevMesh.computeBoundingSphere();
  }
  updateKevMarkers(){
    if(!this.kevMesh)return;
    const matrix=new T.Matrix4();
    this.kevNodes.forEach((node,index)=>{const radius=radiusFor(node.record)+1.8;matrix.compose(new T.Vector3(node.x,node.y,node.z),this.camera.quaternion,new T.Vector3(radius,radius,radius));this.kevMesh.setMatrixAt(index,matrix);});
    this.kevMesh.instanceMatrix.needsUpdate=true;
  }
  setHighlights(events) {this.events=events||[];this.highlightIds=recentEventIds(this.events);this.buildEventRings();this.dirty=true;}
  setNewRecords(ids){
    const fresh=(ids||[]).filter(id=>this.nodeMap.has(id)&&!this.announcedNew.has(id));
    fresh.forEach(id=>this.announcedNew.add(id));
    if(!fresh.length)return;
    this.stage?.dispatchEvent(new CustomEvent('universenewrecords',{bubbles:true,detail:{count:fresh.length}}));
    if(this.reduced.matches||this.paused)return;
    for(const id of fresh.slice(0,Math.max(0,6-this.newTrails.length))){
      const node=this.nodeMap.get(id),end=new T.Vector3(node.x,node.y,node.z),from=end.clone().add(new T.Vector3(-48,92,-46));
      const geometry=new T.BufferGeometry().setFromPoints([from,from]);
      const line=new T.LineSegments(geometry,new T.LineBasicMaterial({color:'#80fff4',transparent:true,opacity:.8,depthWrite:false}));
      this.scene.add(line);this.newTrails.push({id,from,end,line,start:performance.now()});
    }
    this.dirty=true;
  }
  updateNewRecords(time){
    for(const item of [...this.newTrails]){
      const progress=Math.min(1,(time-item.start)/1800),head=item.from.clone().lerp(item.end,1-Math.pow(1-progress,2));
      const tail=item.from.clone().lerp(head,Math.max(0,progress*.85));
      const array=item.line.geometry.getAttribute('position');array.setXYZ(0,tail.x,tail.y,tail.z);array.setXYZ(1,head.x,head.y,head.z);array.needsUpdate=true;
      item.line.geometry.computeBoundingSphere();item.line.material.opacity=(1-progress)*.8;
      if(progress===1){this.scene.remove(item.line);item.line.geometry.dispose();item.line.material.dispose();this.newTrails.splice(this.newTrails.indexOf(item),1);}
    }
    this.dirty=true;
  }
  buildEventRings() {
    if(this.eventMesh){this.scene.remove(this.eventMesh);this.eventMesh.dispose();this.eventMesh=null;}
    this.eventNodes=this.nodes.filter(node=>this.highlightIds.has(node.record.id));
    if(!this.eventNodes.length||this.quality==='low')return;
    this.eventMesh=new T.InstancedMesh(this.eventGeometry,this.eventMaterial,this.eventNodes.length);
    this.scene.add(this.eventMesh);this.updateEventRings();this.eventMesh.computeBoundingSphere();
  }
  updateEventRings() {
    if(!this.eventMesh)return;
    const matrix=new T.Matrix4(),rotation=new T.Quaternion();
    const pulse=1+.07*Math.sin(this.elapsed*.0018);
    for(let i=0;i<this.eventNodes.length;i++) {
      const node=this.eventNodes[i],r=(radiusFor(node.record)+3.5)*pulse;
      matrix.compose(new T.Vector3(node.x,node.y,node.z),rotation,new T.Vector3(r,r,r));
      this.eventMesh.setMatrixAt(i,matrix);
    }
    this.eventMesh.instanceMatrix.needsUpdate=true;
  }
  buildLabels() {
    if(!this.labelsElement)return;
    this.labelsElement.replaceChildren();this.labels=[];
    const groups=new Map();
    for(const node of this.nodes){const group=groups.get(node.vendor);if(group)group.count++;else groups.set(node.vendor,{vendor:node.vendor,count:1,center:node.center});}
    const selected=this.nodeMap.get(this.selected);
    const groupsToShow=selected?[groups.get(selected.vendor)]:[...groups.values()].sort((a,b)=>b.count-a.count||a.vendor.localeCompare(b.vendor)).slice(0,8);
    for(const group of groupsToShow) {
      if(!group)continue;
      const element=document.createElement('span');element.className='universe-label';
      element.textContent=group.vendor;this.labelsElement.append(element);
      this.labels.push({element,position:new T.Vector3(group.center.x,group.center.y,group.center.z)});
    }
  }
  positionLabels() {
    const boxes=[];
    for(const label of this.labels) {
      const p=label.position.clone().project(this.camera);
      const x=(p.x*.5+.5)*this.width,y=(-p.y*.5+.5)*this.height-26;
      const visible=p.z>-1&&p.z<1&&x>75&&x<this.width-75&&y>12&&y<this.height-45&&boxes.every(b=>Math.abs(b.y-y)>29||Math.abs(b.x-x)>165);
      label.element.hidden=!visible;
      if(visible){label.element.style.left=x+'px';label.element.style.top=y+'px';boxes.push({x,y});}
    }
  }
  updateSelection() {
    const node=this.nodeMap.get(this.selected);
    this.selectionRing.visible=!!node;
    this.stage?.classList.toggle('is-focused',!!node);
    if(this.stage){if(node)this.stage.dataset.focusSeverity=String(node.record.severity||'Unknown').toLowerCase();else delete this.stage.dataset.focusSeverity;}
    if(this.links){this.scene.remove(this.links);this.links.geometry.dispose();this.links.material.dispose();this.links=null;}
    this.clearSourceSystem();if(!node)return;
    // White denotes navigation focus; the faceted core continues to encode severity.
    this.selectionRing.material.color.set('#f5fbff');
    this.selectionRing.position.set(node.x,node.y,node.z);this.selectionRing.scale.setScalar(radiusFor(node.record)+5);
    const peers=this.nodes.filter(n=>n.vendor===node.vendor&&n.record.id!==node.record.id).slice(0,32);
    const points=[];for(const peer of peers)points.push(node.x,node.y,node.z,peer.x,peer.y,peer.z);
    if(points.length) {
      const geometry=new T.BufferGeometry();geometry.setAttribute('position',new T.Float32BufferAttribute(points,3));
      this.links=new T.LineSegments(geometry,new T.LineBasicMaterial({color:'#39e6ff',transparent:true,opacity:.25,depthWrite:false}));this.scene.add(this.links);
    }
    this.buildSourceSystem(node);
  }
  clearSourceSystem() {
    if(this.sourceLinks){this.scene.remove(this.sourceLinks);this.sourceLinks.geometry.dispose();this.sourceLinks.material.dispose();this.sourceLinks=null;}
    for(const item of this.sourceSatellites||[]){this.scene.remove(item.mesh);item.mesh.material.dispose();}
    this.sourceSatellites=[];this.sourceCenter=null;
  }
  buildSourceSystem(node) {
    const sources=(node.record.sourceIds||[]).slice(0,8);if(!sources.length)return;
    this.sourceCenter=new T.Vector3(node.x,node.y,node.z);
    this.sourceSatellites=sources.map((source,index)=>{
      const material=new T.MeshBasicMaterial({color:SOURCE_COLORS[source]||'#dce6ee'}),mesh=new T.Mesh(this.sourceGeometry,material);
      mesh.scale.setScalar(1.25);this.scene.add(mesh);return {source,index,mesh};
    });
    const geometry=new T.BufferGeometry();geometry.setAttribute('position',new T.Float32BufferAttribute(new Float32Array(sources.length*6),3));
    this.sourceLinks=new T.LineSegments(geometry,new T.LineBasicMaterial({color:'#8edfea',transparent:true,opacity:.52,depthWrite:false}));
    this.scene.add(this.sourceLinks);this.updateSourceSystem();
  }
  updateSourceSystem() {
    if(!this.sourceCenter||!this.sourceSatellites.length)return;
    const count=this.sourceSatellites.length,radius=15+Math.min(8,count*.8),positions=this.sourceLinks.geometry.getAttribute('position');
    this.sourceSatellites.forEach((item,index)=>{
      const angle=index/count*Math.PI*2+this.elapsed*.00022;
      item.mesh.position.set(this.sourceCenter.x+Math.cos(angle)*radius,this.sourceCenter.y+Math.sin(angle*1.7)*radius*.32,this.sourceCenter.z+Math.sin(angle)*radius);
      const offset=index*6;positions.array[offset]=this.sourceCenter.x;positions.array[offset+1]=this.sourceCenter.y;positions.array[offset+2]=this.sourceCenter.z;
      positions.array[offset+3]=item.mesh.position.x;positions.array[offset+4]=item.mesh.position.y;positions.array[offset+5]=item.mesh.position.z;
    });
    positions.needsUpdate=true;this.sourceLinks.geometry.computeBoundingSphere();
  }
  focus(id,move=true,onArrive) {
    const node=this.nodeMap.get(id);if(!node)return false;
    this.selected=id;this.clearHover();this.updateColors();this.updateSelection();this.buildLabels();
    if(move) {
      const target=new T.Vector3(node.x,node.y,node.z);
      const direction=this.camera.position.clone().sub(this.controls.target).normalize();
      const distance=this.quality==='cinematic'?68:this.quality==='balanced'?82:104;
      this.moveCamera(target.clone().addScaledVector(direction,distance),target,{flight:id,duration:this.firstFlight?1600:1100,onComplete:()=>{this.firstFlight=false;onArrive?.();}});
    } else onArrive?.();
    this.dirty=true;return true;
  }
  beginFlight(id){this.stage?.dispatchEvent(new CustomEvent('universeflightstart',{bubbles:true,detail:{id}}));if(!this.reduced.matches&&!this.paused)this.stage?.classList.add('is-warping');}
  buildFlightClouds(from,to){
    const count=this.quality==='low'?4:12;
    for(let i=0;i<count;i++){
      const t=.18+(i/count)*.62,point=from.clone().lerp(to,t),size=35+from.distanceTo(to)*.09;
      const cloud=new T.Mesh(this.cloudGeometry,cloudMaterial(i%2?'#a7b2c0':'#d5dde7',0));
      cloud.position.copy(point).add(new T.Vector3(Math.sin(i*2.3)*size*.6,Math.cos(i*1.7)*size*.3,0));
      cloud.scale.set(size*(1+i%3*.25),size*.68,1);this.scene.add(cloud);this.flightClouds.push(cloud);
    }
  }
  endFlight(){
    this.stage?.classList.remove('is-warping');
    for(const cloud of this.flightClouds||[]){this.scene?.remove(cloud);cloud.material.dispose();}
    this.flightClouds=[];
  }
  cancelFlight(complete=false){const done=this.transition?.onComplete;this.transition=null;this.endFlight();if(complete)done?.();}
  moveCamera(position,target,options={}) {
    this.cancelFlight();
    if(options.flight)this.beginFlight(options.flight);
    if(this.paused||this.reduced.matches){this.camera.position.copy(position);this.controls.target.copy(target);this.controls.update();this.endFlight();options.onComplete?.();}
    else {
      const from=this.camera.position.clone(),control=from.clone().lerp(position,.5);
      if(options.flight){control.add(new T.Vector3(0,Math.min(65,from.distanceTo(position)*.1),0));this.buildFlightClouds(from,position);}
      this.transition={position:from,control,target:this.controls.target.clone(),endPosition:position,endTarget:target,start:performance.now(),duration:options.duration||600,onComplete:options.onComplete};
    }
    this.dirty=true;
  }
  get zoom(){return HOME_DISTANCE/(this.camera?.position.distanceTo(this.controls.target)||HOME_DISTANCE);}
  setZoom(value) {
    const distance=HOME_DISTANCE/Math.max(.48,Math.min(30,value));
    const direction=this.camera.position.clone().sub(this.controls.target).normalize();
    this.moveCamera(this.controls.target.clone().addScaledVector(direction,distance),this.controls.target.clone());this.clearHover();
  }
  reset() {this.cancelFlight();this.selected=null;this.clearHover();this.updateColors();this.updateSelection();this.buildLabels();this.moveCamera(HOME_DIRECTION.clone().multiplyScalar(HOME_DISTANCE),new T.Vector3());this.options.onReset?.();this.dirty=true;}
  orbit(direction){
    if(direction==='center'){if(this.selected)this.focus(this.selected,true,()=>this.onSelect(this.selected));else this.reset();return;}
    this.cancelFlight(true);
    const spherical=new T.Spherical().setFromVector3(this.camera.position.clone().sub(this.controls.target));
    if(direction==='left')spherical.theta-=.24;if(direction==='right')spherical.theta+=.24;
    if(direction==='up')spherical.phi=Math.max(.1,spherical.phi-.18);if(direction==='down')spherical.phi=Math.min(Math.PI-.1,spherical.phi+.18);
    this.moveCamera(new T.Vector3().setFromSpherical(spherical).add(this.controls.target),this.controls.target.clone());
  }
  setPaused(paused) {
    this.paused=!!paused;
    if(this.paused&&this.transition){const done=this.transition.onComplete;this.camera.position.copy(this.transition.endPosition);this.controls.target.copy(this.transition.endTarget);this.transition=null;this.endFlight();done?.();}
    this.controls.enableDamping=!this.paused&&!this.reduced.matches;this.dirty=true;this.onMotion(this.paused);
  }
  toggle(){this.setPaused(!this.paused);return this.paused;}
  setVisible(visible){this.visible=visible;if(visible)this.resize();else this.clearHover();this.dirty=true;}
  clearHover(){this.hover=null;this.tooltip.hidden=true;this.pendingPointer=null;}
  pick(clientX,clientY,tolerance=0) {
    if(!this.nodeMeshes.length||!this.width||!this.height)return null;
    const rect=this.canvas.getBoundingClientRect();
    this.pointer.set((clientX-rect.left)/rect.width*2-1,-(clientY-rect.top)/rect.height*2+1);
    this.camera.updateMatrixWorld();this.nodeMeshes.forEach(mesh=>mesh.updateMatrixWorld());
    this.raycaster.setFromCamera(this.pointer,this.camera);
    const hit=this.raycaster.intersectObjects(this.nodeMeshes,false)[0];
    if(hit)return hit.object.userData.nodes[hit.instanceId];
    let closest=null,distance=tolerance;
    if(tolerance)for(const node of this.nodes){
      const point=new T.Vector3(node.x,node.y,node.z).project(this.camera);if(point.z<=-1||point.z>=1)continue;
      const d=Math.hypot((point.x*.5+.5)*rect.width-(clientX-rect.left),(-point.y*.5+.5)*rect.height-(clientY-rect.top));
      if(d<distance){distance=d;closest=node;}
    }
    return closest;
  }
  drawMinimap(){
    if(!this.minimap)return;const context=this.minimap.getContext('2d');if(!context)return;
    const w=this.minimap.width,h=this.minimap.height,scale=.12,cx=w/2,cy=h/2;
    context.clearRect(0,0,w,h);context.strokeStyle='#7982b550';context.lineWidth=1;
    context.beginPath();context.ellipse(cx,cy,50,50,0,0,Math.PI*2);context.moveTo(cx,4);context.lineTo(cx,h-4);context.moveTo(4,cy);context.lineTo(w-4,cy);context.stroke();
    const groups=new Map(this.nodes.map(n=>[n.group,n.center]));
    for(const [group,center] of groups){context.fillStyle=this.nodeMap.get(this.selected)?.group===group?'#ff70b9':'#6bbad5';context.beginPath();context.arc(cx+center.x*scale,cy+center.z*scale,2.4,0,Math.PI*2);context.fill();}
    const camera=this.camera.position,target=this.controls.target,dx=camera.x*scale,dz=camera.z*scale,clamp=Math.min(1,53/Math.max(1,Math.hypot(dx,dz))),x=cx+dx*clamp,y=cy+dz*clamp;
    context.strokeStyle='#d0fff0';context.beginPath();context.moveTo(x,y);context.lineTo(cx+target.x*scale,cy+target.z*scale);context.stroke();
    const heading=Math.atan2(target.z-camera.z,target.x-camera.x);context.save();context.translate(x,y);context.rotate(heading);context.fillStyle='#d0fff0';context.beginPath();context.moveTo(6,0);context.lineTo(-4,-4);context.lineTo(-2,0);context.lineTo(-4,4);context.closePath();context.fill();context.restore();
    if(this.axisElement)this.axisElement.textContent=groups.size+' groups · camera '+Math.round(this.zoom*100)+'%';
  }
  showTooltip(pointer) {
    const node=this.pick(pointer.x,pointer.y);this.hover=node;
    if(!node){this.tooltip.hidden=true;return;}
    const r=node.record;this.tooltip.hidden=false;
    this.tooltip.innerHTML='<strong>'+esc(r.id)+'</strong><p>'+esc(String(r.title||r.id).slice(0,140))+'</p><small>CVSS '+metric(r.cvss)+' · EPSS '+percent(r.epss)+(r.kev?' · CISA KEV':'')+'</small>'+(this.highlightIds.has(r.id)?'<small class="accent">Recent saved history event · not live attack traffic</small>':'');
    const rect=this.canvas.getBoundingClientRect();
    this.tooltip.style.left=Math.max(8,Math.min(this.width-285,pointer.x-rect.left+16))+'px';
    this.tooltip.style.top=Math.max(8,Math.min(this.height-135,pointer.y-rect.top+16))+'px';
  }
  frame(time) {
    if(this.disposed)return;
    const delta=Math.max(0,Math.min(.05,(time-(this.previousTime??time))/1000));this.previousTime=time;
    if(!this.visible||document.hidden||!this.width||!this.height)return;
    const motion=!this.paused&&!this.reduced.matches;
    if(motion)this.elapsed+=delta*1000;
    this.controls.autoRotate=motion&&!this.selected&&!this.hover&&!this.activePointers.size&&!this.transition&&this.nodes.length>0;
    this.controls.enableDamping=motion;
    if(this.transition) {
      const t=Math.min(1,(time-this.transition.start)/this.transition.duration),ease=t*t*(3-2*t);
      const a=this.transition.position.clone().lerp(this.transition.control,ease),b=this.transition.control.clone().lerp(this.transition.endPosition,ease);
      this.camera.position.lerpVectors(a,b,ease);
      this.controls.target.lerpVectors(this.transition.target,this.transition.endTarget,ease);
      for(const cloud of this.flightClouds)cloud.material.opacity=Math.sin(Math.PI*t)*.48;
      if(t>=1){const done=this.transition.onComplete;this.transition=null;this.endFlight();done?.();}
      this.dirty=true;
    }
    if(this.controls.update(delta))this.dirty=true;
    if(this.pendingPointer&&!this.drag){const pointer=this.pendingPointer;this.pendingPointer=null;this.showTooltip(pointer);}
    if(motion&&this.eventMesh){this.updateEventRings();this.dirty=true;}
    if(motion&&this.sourceSatellites.length){this.updateSourceSystem();this.dirty=true;}
    if(this.newTrails.length)this.updateNewRecords(motion?time:Infinity);
    if(!this.dirty)return;
    this.updateKevMarkers();
    for(const cloud of [...this.clouds,...this.flightClouds])cloud.quaternion.copy(this.camera.quaternion);
    this.selectionRing.quaternion.copy(this.camera.quaternion);
    if(this.composer)this.composer.render(delta);else this.renderer.render(this.scene,this.camera);
    this.positionLabels();this.drawMinimap();this.dirty=false;
  }
  dispose() {
    if(this.disposed)return;this.disposed=true;this.abort?.abort();this.cancelFlight();
    this.renderer?.setAnimationLoop(null);this.resizeObserver?.disconnect();
    if(this.motionHandler)this.reduced?.removeEventListener('change',this.motionHandler);
    this.controls?.dispose();this.disposeComposer();
    this.clearSourceSystem();
    const geometries=new Set([...Object.values(this.nodeGeometries||{}),this.haloGeometry,this.cloudGeometry,this.eventGeometry,this.kevGeometry,this.sourceGeometry]);
    const materials=new Set([this.nodeMaterial,this.glowMaterial,this.coronaMaterial,this.eventMaterial,this.kevMaterial]);
    this.scene?.traverse(object=>{if(object.geometry)geometries.add(object.geometry);if(object.material)for(const material of [object.material].flat())materials.add(material);});
    for(const geometry of geometries)geometry?.dispose();for(const material of materials)material?.dispose();
    for(const mesh of this.nodeMeshes)mesh.dispose();this.starfield?.dispose();this.glowMesh?.dispose();this.coronaMesh?.dispose();this.eventMesh?.dispose();this.kevMesh?.dispose();this.renderer?.dispose();
    this.labelsElement?.replaceChildren();this.tooltip.hidden=true;
  }
}
