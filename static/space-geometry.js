/* Local geometry helpers. Scenery has no record IDs and cannot be investigated. */
import * as T from './vendor/three.js';

export function crystal(sides=5,height=1.3,radius=.85){
  const vertices=[];
  for(let i=0;i<sides;i++){
    const a=i/sides*Math.PI*2,b=(i+1)/sides*Math.PI*2;
    const left=[Math.cos(a)*radius,0,Math.sin(a)*radius],right=[Math.cos(b)*radius,0,Math.sin(b)*radius];
    vertices.push(0,height,0,...right,...left,0,-height,0,...left,...right);
  }
  const geometry=new T.BufferGeometry();geometry.setAttribute('position',new T.Float32BufferAttribute(vertices,3));geometry.computeVertexNormals();return geometry;
}

export function cloudPlane(){
  const geometry=new T.BufferGeometry();
  geometry.setAttribute('position',new T.Float32BufferAttribute([-1,-1,0,1,-1,0,1,1,0,-1,-1,0,1,1,0,-1,1,0],3));
  geometry.computeVertexNormals();return geometry;
}

export function cloudMaterial(color,opacity){
  const material=new T.MeshBasicMaterial({color,transparent:true,opacity,depthWrite:false,depthTest:true});
  material.onBeforeCompile=shader=>{
    shader.vertexShader=shader.vertexShader.replace('#include <common>','#include <common>\nvarying vec2 mmCloudUV;')
      .replace('#include <begin_vertex>','#include <begin_vertex>\nmmCloudUV = position.xy;');
    shader.fragmentShader=shader.fragmentShader.replace('#include <common>',`#include <common>
      varying vec2 mmCloudUV;
      float mmHash(vec2 p){return fract(sin(dot(p,vec2(127.1,311.7)))*43758.5453);}
      float mmNoise(vec2 p){vec2 i=floor(p),f=fract(p);f=f*f*(3.0-2.0*f);
        return mix(mix(mmHash(i),mmHash(i+vec2(1.,0.)),f.x),mix(mmHash(i+vec2(0.,1.)),mmHash(i+vec2(1.,1.)),f.x),f.y);}
      float mmCloud(vec2 p){return .56*mmNoise(p)+.28*mmNoise(p*2.03+4.1)+.16*mmNoise(p*4.07+9.3);}`)
      .replace('#include <color_fragment>',`#include <color_fragment>
        float edge = 1.0-smoothstep(.12,1.0,length(mmCloudUV));
        float cloud = smoothstep(.15,.85,mmCloud(mmCloudUV*3.0+2.7));
        diffuseColor.a *= edge*cloud;
        if(diffuseColor.a < .001) discard;`);
  };
  material.customProgramCacheKey=()=> 'mastermonk-cloud-v1';
  return material;
}
