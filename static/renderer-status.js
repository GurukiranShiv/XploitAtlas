// A selected compatibility mode is information, not an error.
export function rendererPresentation(status) {
  const mode=status.mode;
  const label=mode==='webgl'?'Renderer: WebGL 3D':mode==='canvas'?'Renderer: Canvas 2D':'Renderer: table only';
  const notice=status.reason||(mode==='table'?'Graphics could not start. Your records remain available in Table.':'');
  return {label,notice,warning:!!notice};
}
