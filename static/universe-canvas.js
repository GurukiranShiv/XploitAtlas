/* Perspective projection of real records. Seeded positions are layout, never data. */
import {escapeHTML, metric, percent} from './ui.js';
import {layoutRecords, colorFor, visualSignature} from './universe-layout.js';

export class CanvasUniverse {
  constructor(canvas, tooltip, onSelect, onMotion) {
    this.mode='canvas';
    this.canvas=canvas;this.tooltip=tooltip;this.onSelect=onSelect;this.onMotion=onMotion;
    this.ctx=canvas.getContext('2d',{alpha:false});
    this.nodes=[];this.projected=[];this.yaw=.4;this.pitch=.17;this.zoom=1;
    this.selected=null;this.hover=null;this.pointer=null;this.drag=null;this.visible=true;
    this.reduced=window.matchMedia('(prefers-reduced-motion: reduce)');
    this.paused=this.reduced.matches;
    this.lastFrame=0;this.dirty=true;this.disposed=false;
    this.resizeObserver=new ResizeObserver(()=>this.resize());this.resizeObserver.observe(canvas);
    this.motionHandler=event=>{if(event.matches){this.paused=true;this.onMotion(true);}this.dirty=true;};
    this.reduced.addEventListener('change',this.motionHandler);
    this.bind();
    this.frame=this.frame.bind(this);this.raf=requestAnimationFrame(this.frame);
  }
  bind() {
    this.canvas.addEventListener('pointerdown',e=>{
      if(e.button!==0) return;
      const rect=this.canvas.getBoundingClientRect();this.pointer={x:e.clientX-rect.left,y:e.clientY-rect.top};
      this.drag={id:e.pointerId,x:e.clientX,y:e.clientY,startX:e.clientX,startY:e.clientY,moved:false};
      this.canvas.setPointerCapture(e.pointerId);
      this.tooltip.hidden=true;
    });
    this.canvas.addEventListener('pointermove',e=>{
      const rect=this.canvas.getBoundingClientRect();
      this.pointer={x:e.clientX-rect.left,y:e.clientY-rect.top};
      if(this.drag) {
        const dx=e.clientX-this.drag.x,dy=e.clientY-this.drag.y;
        if(Math.hypot(e.clientX-this.drag.startX,e.clientY-this.drag.startY)>5) this.drag.moved=true;
        this.yaw+=dx*.006;this.pitch=Math.max(-1.25,Math.min(1.25,this.pitch+dy*.005));
        this.drag.x=e.clientX;this.drag.y=e.clientY;this.dirty=true;
      } else this.hitTest();
    });
    this.canvas.addEventListener('pointerup',e=>{
      const drag=this.drag;
      if(!drag||drag.id!==e.pointerId) return;
      this.drag=null;
      if(this.canvas.hasPointerCapture(e.pointerId)) this.canvas.releasePointerCapture(e.pointerId);
      if(!drag.moved) {
        this.hitTest();
        if(this.hover){this.selected=this.hover.record.id;this.onSelect(this.hover.record.id);}
      }
      this.dirty=true;
    });
    this.canvas.addEventListener('pointercancel',()=>{this.drag=null;this.tooltip.hidden=true;});
    this.canvas.addEventListener('pointerleave',()=>{if(!this.drag){this.pointer=null;this.hover=null;this.tooltip.hidden=true;this.dirty=true;}});
    this.canvas.addEventListener('wheel',e=>{e.preventDefault();this.setZoom(this.zoom*Math.exp(-e.deltaY*.001));},{passive:false});
    this.canvas.addEventListener('keydown',e=>{
      if(e.key==='ArrowLeft')this.yaw-=.12;
      else if(e.key==='ArrowRight')this.yaw+=.12;
      else if(e.key==='ArrowUp')this.pitch=Math.max(-1.25,this.pitch-.1);
      else if(e.key==='ArrowDown')this.pitch=Math.min(1.25,this.pitch+.1);
      else if(e.key==='+'||e.key==='=')this.setZoom(this.zoom*1.15);
      else if(e.key==='-')this.setZoom(this.zoom/1.15);
      else if(e.key==='Home')this.reset();
      else if(e.key===' '){this.toggle();this.onMotion(this.paused);}
      else return;
      e.preventDefault();this.dirty=true;
    });
  }
  resize() {
    const rect=this.canvas.getBoundingClientRect();
    if(!rect.width||!rect.height) return;
    this.width=rect.width;this.height=rect.height;
    const ratio=Math.min(window.devicePixelRatio||1,2);
    this.canvas.width=Math.round(rect.width*ratio);this.canvas.height=Math.round(rect.height*ratio);
    this.ctx?.setTransform(ratio,0,0,ratio,0,0);this.dirty=true;
  }
  setRecords(records,grouping='vendor') {
    const signature=visualSignature(records,grouping);
    if(signature===this.signature){const current=new Map(records.map(r=>[r.id,r]));for(const node of this.nodes)node.record=current.get(node.record.id);this.dirty=true;return;}
    this.signature=signature;this.nodes=layoutRecords(records,grouping);this.hover=null;this.tooltip.hidden=true;this.dirty=true;
  }
  setVisible(visible) {this.visible=visible;if(visible){this.resize();this.dirty=true;}}
  setZoom(value){this.zoom=Math.max(.55,Math.min(3.3,value));this.tooltip.hidden=true;this.dirty=true;}
  reset(){this.yaw=.4;this.pitch=.17;this.zoom=1;this.selected=null;this.onSelect(null);this.dirty=true;}
  toggle(){this.paused=!this.paused;this.dirty=true;return this.paused;}
  setPaused(paused){this.paused=!!paused;this.dirty=true;}
  focus(id){this.selected=id;this.dirty=true;return this.nodes.some(n=>n.record.id===id);}
  orbit(direction){if(direction==='left')this.yaw-=.16;else if(direction==='right')this.yaw+=.16;else if(direction==='up')this.pitch=Math.max(-1.25,this.pitch-.12);else if(direction==='down')this.pitch=Math.min(1.25,this.pitch+.12);this.dirty=true;}
  setNewRecords(){} // New-observation flight is a WebGL feature.
  setHighlights(){} // Saved-history rings are available in WebGL mode only.
  dispose(){this.disposed=true;cancelAnimationFrame(this.raf);this.resizeObserver.disconnect();this.reduced.removeEventListener('change',this.motionHandler);this.tooltip.hidden=true;}
  project(point) {
    const cy=Math.cos(this.yaw),sy=Math.sin(this.yaw),cp=Math.cos(this.pitch),sp=Math.sin(this.pitch);
    const x=point.x*cy-point.z*sy,z=point.x*sy+point.z*cy;
    const y=point.y*cp-z*sp,depth=point.y*sp+z*cp;
    const distance=750/this.zoom;
    const scale=Math.min(this.width,this.height)*1.42/(distance+depth);
    return {x:this.width/2+x*scale,y:this.height/2+y*scale,depth,scale,behind:distance+depth<50};
  }
  ring(radius, tilt) {
    const ctx=this.ctx;ctx.beginPath();
    let started=false;
    for(let i=0;i<=90;i++){
      const angle=i/90*Math.PI*2;
      const p=this.project({x:Math.cos(angle)*radius,y:Math.sin(angle)*radius*Math.sin(tilt),z:Math.sin(angle)*radius*Math.cos(tilt)});
      if(p.behind){started=false;continue;}
      if(!started){ctx.moveTo(p.x,p.y);started=true;}else ctx.lineTo(p.x,p.y);
    }
    ctx.stroke();
  }
  draw() {
    if(!this.ctx||!this.width||!this.height)return;
    const ctx=this.ctx;
    ctx.fillStyle='#03030a';ctx.fillRect(0,0,this.width,this.height);
    const glow=ctx.createRadialGradient(this.width*.5,this.height*.5,0,this.width*.5,this.height*.5,this.width*.52);
    glow.addColorStop(0,'#17143b');glow.addColorStop(.58,'#0a0a20');glow.addColorStop(1,'#03030a');
    ctx.fillStyle=glow;ctx.fillRect(0,0,this.width,this.height);
    if(!this.nodes.length)return;
    ctx.lineWidth=.65;ctx.strokeStyle='#5567aa42';
    this.ring(290,0);this.ring(290,.9);this.ring(290,-.9);
    ctx.strokeStyle='#3d487d35';this.ring(190,0);
    this.projected=this.nodes.map(node=>{
      const p=this.project(node);
      const cvss=node.record.cvss;
      const base=typeof cvss==='number'?1.2+cvss*.21:1.6;
      return {...node,...p,radius:Math.max(1.2,Math.min(8,base*p.scale)),color:colorFor(node.record)};
    }).filter(node=>!node.behind && node.x>-40 && node.x<this.width+40 && node.y>-40 && node.y<this.height+40).sort((a,b)=>b.depth-a.depth);
    const focus=this.projected.find(p=>p.record.id===(this.hover?.record.id||this.selected));
    if(focus) {
      const peers=this.projected.filter(n=>n.vendor===focus.vendor && n.record.id!==focus.record.id);
      ctx.strokeStyle='#39e6ff48';ctx.lineWidth=.7;
      for(const node of peers.slice(0,60)){ctx.beginPath();ctx.moveTo(focus.x,focus.y);ctx.lineTo(node.x,node.y);ctx.stroke();}
    }
    for(const node of this.projected) {
      const emphasized=focus && (focus.record.id===node.record.id || focus.vendor===node.vendor);
      const muted=focus && !emphasized;
      ctx.globalAlpha=muted ? .22 :Math.max(.3,Math.min(.95,.8-node.depth/800));
      if(node.record.kev && !muted) {
        ctx.beginPath();ctx.strokeStyle='#ff3c62';ctx.lineWidth=.9;
        ctx.arc(node.x,node.y,node.radius+2.5,0,Math.PI*2);ctx.stroke();
      }
      ctx.beginPath();ctx.fillStyle=node.color;ctx.arc(node.x,node.y,node.radius,0,Math.PI*2);ctx.fill();
    }
    ctx.globalAlpha=1;
    if(focus) {
      const node=this.projected.find(p=>p.record.id===focus.record.id);
      if(node){
        ctx.beginPath();ctx.strokeStyle='#c8fbff';ctx.lineWidth=1;
        ctx.arc(node.x,node.y,node.radius+6,0,Math.PI*2);ctx.stroke();
        ctx.font='10px ui-monospace,Consolas,monospace';ctx.fillStyle='#b8f6ff';
        const label=node.vendor.length>38?node.vendor.slice(0,35)+'…':node.vendor;
        ctx.fillText(label,Math.max(10,Math.min(this.width-ctx.measureText(label).width-10,node.x+15)),Math.max(20,node.y-14));
      }
    } else {
      const counted=new Map();
      for(const node of this.nodes) counted.set(node.vendor,(counted.get(node.vendor)||0)+1);
      const top=[...counted.entries()].sort((a,b)=>b[1]-a[1]).slice(0,5);
      const boxes=[];
      ctx.font='9px ui-monospace,Consolas,monospace';ctx.fillStyle='#7ea6bf';
      for(const [vendor] of top) {
        const member=this.nodes.find(n=>n.vendor===vendor);
        const p=this.project(member.center),label=vendor.length>23?vendor.slice(0,20)+'…':vendor;
        const w=ctx.measureText(label).width;
        const x=Math.max(15,Math.min(this.width-w-15,p.x-w/2)),y=Math.max(20,Math.min(this.height-15,p.y-35));
        if(!p.behind && boxes.every(b=>Math.abs(b.y-y)>15 || x>b.x+b.w+10 || x+w<b.x-10)){ctx.fillText(label,x,y);boxes.push({x,y,w});}
      }
    }
  }
  hitTest() {
    if(!this.pointer||this.drag)return;
    let nearest=null,best=Infinity;
    for(const node of this.projected) {
      const distance=Math.hypot(node.x-this.pointer.x,node.y-this.pointer.y);
      if(distance<Math.max(9,node.radius+5)&&distance<best){nearest=node;best=distance;}
    }
    const changed=this.hover?.record.id!==nearest?.record.id;
    this.hover=nearest;
    if(changed)this.dirty=true;
    if(!nearest){this.tooltip.hidden=true;return;}
    this.tooltip.hidden=false;
    this.tooltip.innerHTML='<strong>'+escapeHTML(nearest.record.id)+'</strong><p>'+escapeHTML(nearest.record.title.slice(0,130))+'</p><small>CVSS '+metric(nearest.record.cvss)+' · EPSS '+percent(nearest.record.epss)+(nearest.record.kev?' · CISA KEV':'')+'</small>';
    this.tooltip.style.left=Math.max(8,Math.min(this.width-285,this.pointer.x+17))+'px';
    this.tooltip.style.top=Math.max(8,Math.min(this.height-100,this.pointer.y+15))+'px';
  }
  frame(timestamp) {
    if(this.disposed)return;
    const elapsed=Math.min(50,timestamp-(this.lastFrame||timestamp));
    this.lastFrame=timestamp;
    if(this.visible&&!document.hidden) {
      if(!this.paused&&!this.drag&&!this.hover&&this.nodes.length){this.yaw+=elapsed*.000025;this.dirty=true;}
      if(this.dirty){this.draw();this.dirty=false;}
    }
    this.raf=requestAnimationFrame(this.frame);
  }
}
