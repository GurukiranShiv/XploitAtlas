/* The catalog does not depend on WebGL. GPU failures can use Canvas or Table. */
import {CanvasUniverse} from './universe-canvas.js';
export {hash,layoutRecords,colorFor} from './universe-layout.js';

const QUALITIES=['balanced','low','cinematic','canvas'];
export class Universe {
  constructor(canvas,tooltip,onSelect,onMotion,onStatus=()=>{}) {
    this.canvas=canvas;this.tooltip=tooltip;this.onSelect=onSelect;this.onMotion=onMotion;this.onStatus=onStatus;
    this.records=[];this.events=[];this.visible=true;this.ready=false;this.engine=null;this.generation=0;
    this.grouping='vendor';this.newRecordIds=[];
    this.pausedValue=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    this.quality=window.matchMedia('(max-width: 760px)').matches||navigator.maxTouchPoints>1?'low':'balanced';this.selection=null;
    this.motionChanged=paused=>{this.pausedValue=paused;this.onMotion(paused);};
    this.selectionChanged=id=>{this.selection=id;this.onSelect(id);};
    try{const saved=sessionStorage.getItem('mastermonk-osint-graphics');if(QUALITIES.includes(saved))this.quality=saved;}catch{/* Preferences are optional. */}
    this.initialize();
  }
  get paused(){return this.engine?.paused??this.pausedValue;}
  get zoom(){return this.engine?.zoom??1;}
  get selected(){return this.engine?.selected??this.selection;}
  get available(){return !!this.engine?.ctx;}
  replaceCanvas() {
    const canvas=this.canvas.cloneNode(false);this.canvas.replaceWith(canvas);this.canvas=canvas;
    document.querySelector('#vendor-labels')?.replaceChildren();
    return canvas;
  }
  async initialize() {
    const generation=++this.generation;this.ready=false;
    this.pausedValue=this.paused;this.engine?.dispose();this.engine=null;
    // A canvas cannot switch context types; replace only the drawing element.
    const canvas=this.replaceCanvas();let reason='';
    await Promise.resolve(); // Status callbacks run after construction.
    try {
      if(this.quality!=='canvas') {
        const {WebGLUniverse}=await import('./universe-webgl.js');
        if(generation!==this.generation)return;
        this.engine=new WebGLUniverse(canvas,this.tooltip,this.selectionChanged,this.motionChanged,{
          quality:this.quality,labelsElement:document.querySelector('#vendor-labels'),
          minimap:document.querySelector('#universe-minimap'),axisElement:document.querySelector('#universe-axis'),
          onReset:()=>this.selectionChanged(null),
          onContextLost:()=>this.fallback('The graphics context was lost. Your catalog remains available.'),
          onRenderError:()=>this.fallback('The GPU renderer could not continue. Canvas mode is available.')
        });
      }
    }catch(error) {
      console.error('MasterMonk WebGL renderer could not start.',error);
      reason='WebGL 3D could not start'+(error?.message?': '+error.message:'.')+' Canvas mode keeps the catalog available.';
    }
    if(generation!==this.generation)return;
    if(!this.engine)this.createCanvasEngine();
    this.restoreState();this.report(reason);
  }
  createCanvasEngine() {
    try{this.engine=new CanvasUniverse(this.replaceCanvas(),this.tooltip,this.selectionChanged,this.motionChanged);}
    catch{this.engine=null;}
  }
  restoreState() {
    this.ready=true;this.engine?.setPaused(this.pausedValue);
    this.engine?.setRecords(this.records,this.grouping);this.engine?.setHighlights(this.events);
    this.engine?.setVisible(this.visible);
    if(this.selection)this.engine?.focus(this.selection,false);
  }
  report(reason='') {
    this.onStatus({mode:this.available?this.engine.mode:'table',
      quality:this.engine?.mode==='webgl'?this.engine.quality:this.quality,reason});
  }
  fallback(reason) {
    this.generation++;this.pausedValue=this.paused;
    this.engine?.dispose();this.engine=null;this.createCanvasEngine();this.restoreState();this.report(reason);
  }
  setRecords(records,grouping=this.grouping) {
    this.records=records;this.grouping=grouping;this.engine?.setRecords(records,grouping);
    if(this.selection&&!records.some(r=>r.id===this.selection))this.selectionChanged(null);
  }
  setHighlights(events){this.events=events||[];this.engine?.setHighlights(this.events);}
  setNewRecords(ids){this.newRecordIds=ids||[];this.engine?.setNewRecords?.(this.newRecordIds);}
  setGrouping(value){if(!['vendor','weakness','severity','source'].includes(value))return;this.grouping=value;this.engine?.setRecords(this.records,value);}
  setVisible(visible){this.visible=visible;this.engine?.setVisible(visible);}
  setZoom(value){this.engine?.setZoom(value);}
  focus(id,move=true){
    if(this.engine?.mode==='webgl')return this.engine.focus(id,move,()=>this.selectionChanged(id));
    const result=this.engine?.focus(id,move)||false;if(result)this.selectionChanged(id);return result;
  }
  orbit(direction){this.engine?.orbit?.(direction);}
  reset(){this.engine?.reset();this.selectionChanged(null);}
  toggle(){this.pausedValue=!this.paused;this.engine?.setPaused(this.pausedValue);return this.pausedValue;}
  setQuality(value) {
    if(!QUALITIES.includes(value))return;
    this.quality=value;try{sessionStorage.setItem('mastermonk-osint-graphics',value);}catch{/* Optional preference. */}
    if(this.engine?.mode==='webgl'&&value!=='canvas'){this.engine.setQuality(value);this.report();}
    else this.initialize();
  }
  dispose(){this.generation++;this.engine?.dispose();this.engine=null;}
}
