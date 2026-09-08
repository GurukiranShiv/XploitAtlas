/* Genuine WebGL graph. Nodes and edges are supplied only by recorded evidence. */
import * as T from './vendor/three.js';
const colors={package:'#ffc76e',advisory:'#46d9ff',vulnerability:'#b888ff',exploitation:'#ff537a',fix:'#54efb7',statement:'#b9c6fb'};

export class EvidenceGraph{
  constructor(canvas,labels,model,onSelect,onFailure){
    this.canvas=canvas;this.labels=labels;this.model=model;this.onSelect=onSelect;this.onFailure=onFailure;
    this.disposed=false;this.dirty=true;this.meshes=[];this.nodeMap=new Map();this.labelItems=[];this.abort=new AbortController();
    this.reduced=matchMedia('(prefers-reduced-motion: reduce)');
    try{this.setup();}catch(error){this.dispose();throw error;}
  }
  setup(){
    this.renderer=new T.WebGLRenderer({canvas:this.canvas,antialias:true,alpha:false,powerPreference:'default'});
    this.renderer.setClearColor(0x08091f,1);this.renderer.outputColorSpace=T.SRGBColorSpace;
    this.renderer.toneMapping=T.ACESFilmicToneMapping;this.renderer.toneMappingExposure=1.2;
    this.scene=new T.Scene();this.camera=new T.PerspectiveCamera(42,1,1,2400);this.camera.position.set(220,130,590);
    this.scene.add(new T.AmbientLight('#d5e8ff',1.5));const light=new T.DirectionalLight('#ffffff',2.4);light.position.set(-100,250,400);this.scene.add(light);
    this.controls=new T.OrbitControls(this.camera,this.canvas);this.controls.enableDamping=true;this.controls.dampingFactor=.12;
    this.controls.minDistance=70;this.controls.maxDistance=1300;this.controls.target.set(20,0,0);
    this.controls.rotateSpeed=.46;this.controls.panSpeed=.45;this.controls.zoomSpeed=.68;
    this.controls.minPolarAngle=.12;this.controls.maxPolarAngle=Math.PI-.12;
    this.controls.addEventListener('change',()=>this.dirty=true);this.controls.addEventListener('start',()=>this.transition=null);
    this.geometry=new T.SphereGeometry(1,20,14);this.raycaster=new T.Raycaster();this.pointer=new T.Vector2();
    const columns=new Map();
    this.model.nodes.forEach(node=>{if(!columns.has(node.column))columns.set(node.column,[]);columns.get(node.column).push(node);});
    this.model.nodes.forEach(node=>{
      const peers=columns.get(node.column),index=peers.indexOf(node);
      const angle=index/Math.max(3,peers.length)*Math.PI*2+node.column*.48,radius=peers.length===1?0:55+Math.min(110,peers.length*7);
      const position=new T.Vector3((node.column-1.7)*100,Math.cos(angle)*radius,Math.sin(angle)*radius);
      const material=new T.MeshStandardMaterial({color:colors[node.kind]||'#bac4d1',roughness:.3,metalness:.12,emissive:colors[node.kind]||'#bac4d1',emissiveIntensity:.1});
      const mesh=new T.Mesh(this.geometry,material);mesh.position.copy(position);mesh.scale.setScalar(node.kind==='package'?10:node.kind==='exploitation'?9:7);
      mesh.userData.node=node;this.scene.add(mesh);this.meshes.push(mesh);this.nodeMap.set(node.id,{node,position,mesh});
      const label=document.createElement('button');label.type='button';label.className='graph-label';label.textContent=node.label;
      label.addEventListener('click',()=>this.focus(node.id),{signal:this.abort.signal});
      this.labels.append(label);this.labelItems.push({element:label,position,node});
    });
    this.drawEdges();
    this.ring=new T.Mesh(new T.TorusGeometry(1,.03,8,48),new T.MeshBasicMaterial({color:'#f6ddba',transparent:true,opacity:.9}));
    this.ring.visible=false;this.scene.add(this.ring);
    this.activePointers=new Set();
    this.listen(this.canvas,'pointerdown',event=>{
      this.activePointers.add(event.pointerId);
      this.drag=this.activePointers.size===1?{x:event.clientX,y:event.clientY,id:event.pointerId}:null;
    });
    this.listen(this.canvas,'pointerup',event=>{
      const d=this.drag;this.drag=null;this.activePointers.delete(event.pointerId);if(!d||d.id!==event.pointerId||Math.hypot(event.clientX-d.x,event.clientY-d.y)>(event.pointerType==='touch'?12:6))return;
      const rect=this.canvas.getBoundingClientRect();this.pointer.set((event.clientX-rect.left)/rect.width*2-1,-(event.clientY-rect.top)/rect.height*2+1);
      this.camera.updateMatrixWorld();this.scene.updateMatrixWorld();this.raycaster.setFromCamera(this.pointer,this.camera);
      const hit=this.raycaster.intersectObjects(this.meshes,false)[0];if(hit)this.focus(hit.object.userData.node.id);
      else if(event.pointerType==='touch'){
        let closest=null,distance=24;
        for(const item of this.nodeMap.values()){const point=item.position.clone().project(this.camera);if(point.z<=-1||point.z>=1)continue;
          const d=Math.hypot((point.x*.5+.5)*rect.width-(event.clientX-rect.left),(-point.y*.5+.5)*rect.height-(event.clientY-rect.top));
          if(d<distance){closest=item;distance=d;}}
        if(closest)this.focus(closest.node.id);
      }
    });
    this.listen(this.canvas,'pointercancel',event=>{this.drag=null;this.activePointers.delete(event.pointerId);});
    this.listen(this.canvas,'keydown',event=>{
      const directions={ArrowLeft:'left',ArrowRight:'right',ArrowUp:'up',ArrowDown:'down'};
      if(directions[event.key]){event.preventDefault();this.orbit(directions[event.key]);return;}
      if(['+','=','-','Home'].includes(event.key)){
        event.preventDefault();this.transition=null;if(event.key==='Home'){this.camera.position.set(220,130,590);this.controls.target.set(20,0,0);}
        else this.camera.position.sub(this.controls.target).multiplyScalar(event.key==='-'?1.2:1/1.2).add(this.controls.target);
        this.controls.update();this.dirty=true;
      }
    });
    this.listen(this.canvas,'webglcontextlost',event=>{event.preventDefault();this.dispose();this.onFailure?.();});
    this.observer=new ResizeObserver(()=>this.resize());this.observer.observe(this.canvas);this.resize();
    this.renderer.setAnimationLoop(time=>{try{this.frame(time);}catch{this.dispose();this.onFailure?.();}});
  }
  listen(target,type,callback){target.addEventListener(type,callback,{signal:this.abort.signal});}
  drawEdges(){
    if(this.lines){this.scene.remove(this.lines);this.lines.geometry.dispose();this.lines.material.dispose();}
    const vertices=[],lineColors=[];
    for(const edge of this.model.edges){
      const from=this.nodeMap.get(edge.from),to=this.nodeMap.get(edge.to);if(!from||!to)continue;
      vertices.push(from.position.x,from.position.y,from.position.z,to.position.x,to.position.y,to.position.z);
      const selected=!this.selected||edge.from===this.selected||edge.to===this.selected;
      const color=new T.Color(selected?'#5de8ed':'#353353');lineColors.push(color.r,color.g,color.b,color.r,color.g,color.b);
    }
    const geometry=new T.BufferGeometry();geometry.setAttribute('position',new T.Float32BufferAttribute(vertices,3));geometry.setAttribute('color',new T.Float32BufferAttribute(lineColors,3));
    this.lines=new T.LineSegments(geometry,new T.LineBasicMaterial({vertexColors:true,transparent:true,opacity:.75}));this.scene.add(this.lines);
  }
  focus(id){
    const selected=this.nodeMap.get(id);if(!selected||this.disposed)return;
    this.selected=id;this.drawEdges();this.ring.visible=true;this.ring.position.copy(selected.position);this.ring.scale.setScalar(selected.mesh.scale.x*1.6);
    const direction=this.camera.position.clone().sub(this.controls.target).normalize();
    const target=selected.position.clone(),destination=target.clone().add(direction.multiplyScalar(230));
    if(this.reduced.matches){this.controls.target.copy(target);this.camera.position.copy(destination);this.controls.update();}
    else this.transition={started:performance.now(),from:this.camera.position.clone(),to:destination,fromTarget:this.controls.target.clone(),target};
    this.meshes.forEach(mesh=>{const related=mesh.userData.node.id===id||this.model.edges.some(e=>(e.from===id&&e.to===mesh.userData.node.id)||(e.to===id&&e.from===mesh.userData.node.id));
      mesh.material.color.set(colors[mesh.userData.node.kind]||'#bac4d1');if(!related)mesh.material.color.multiplyScalar(.3);
    });
    this.onSelect(selected.node);this.dirty=true;
  }
  resize(){
    if(this.disposed||!this.renderer)return;const rect=this.canvas.getBoundingClientRect();if(!rect.width||!rect.height)return;
    this.width=rect.width;this.height=rect.height;this.renderer.setPixelRatio(Math.min(devicePixelRatio||1,1.5));
    this.renderer.setSize(rect.width,rect.height,false);this.camera.aspect=rect.width/rect.height;this.camera.updateProjectionMatrix();this.dirty=true;
  }
  orbit(direction){
    this.transition=null;
    if(direction==='reset'){this.camera.position.set(220,130,590);this.controls.target.set(20,0,0);}
    else{
      const offset=this.camera.position.clone().sub(this.controls.target),spherical=new T.Spherical().setFromVector3(offset);
      if(direction==='left')spherical.theta-=.23;if(direction==='right')spherical.theta+=.23;
      if(direction==='up')spherical.phi=Math.max(.12,spherical.phi-.18);if(direction==='down')spherical.phi=Math.min(Math.PI-.12,spherical.phi+.18);
      if(direction==='in')spherical.radius=Math.max(70,spherical.radius/1.2);if(direction==='out')spherical.radius=Math.min(1300,spherical.radius*1.2);
      this.camera.position.setFromSpherical(spherical).add(this.controls.target);
    }
    this.controls.update();this.dirty=true;
  }
  frame(time){
    if(this.disposed||document.hidden)return;
    if(this.transition){const t=this.transition,p=Math.min(1,(time-t.started)/600),ease=1-Math.pow(1-p,3);
      this.camera.position.lerpVectors(t.from,t.to,ease);this.controls.target.lerpVectors(t.fromTarget,t.target,ease);this.dirty=true;if(p>=1)this.transition=null;
    }
    this.controls.update();if(!this.dirty)return;this.dirty=false;
    if(this.ring?.visible)this.ring.quaternion.copy(this.camera.quaternion);
    this.renderer.render(this.scene,this.camera);
    const occupied=[];
    for(const item of this.labelItems){
      const projected=item.position.clone().project(this.camera),x=(projected.x*.5+.5)*this.width,y=(-projected.y*.5+.5)*this.height+18;
      const visible=projected.z>-1&&projected.z<1&&x>15&&x<this.width-15&&y>15&&y<this.height-15&&
        (item.node.id===this.selected||occupied.every(p=>Math.abs(p.x-x)>115||Math.abs(p.y-y)>28));
      item.element.hidden=!visible;
      if(visible){item.element.style.left=x+'px';item.element.style.top=y+'px';occupied.push({x,y});}
    }
  }
  dispose(){
    if(this.disposed)return;this.disposed=true;this.abort.abort();this.observer?.disconnect();this.renderer?.setAnimationLoop(null);
    this.controls?.dispose();this.geometry?.dispose();this.meshes.forEach(mesh=>mesh.material.dispose());
    this.lines?.geometry.dispose();this.lines?.material.dispose();this.ring?.geometry.dispose();this.ring?.material.dispose();
    this.renderer?.dispose();this.labels?.replaceChildren();
  }
}
