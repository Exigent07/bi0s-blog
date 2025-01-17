export default function Outline({
  children, 
  className = "w-fit h-fit",
  outlineColor = "bg-deep",
  style = {},
  length = 2.5,
}) {
  return (
    <div 
      className={`outlinedElement relative ${className}`} 
      style={style}
    >
      <div className="outline-container h-full w-full pointer-events-none absolute inset-0">
        <div 
          className={`outline-top absolute h-[1px] w-full left-1/2 -translate-x-1/2 ${outlineColor}`} 
          style={{ top: `${length}px` }}
        ></div>
        <div 
          className={`outline-bottom absolute h-[1px] w-full left-1/2 -translate-x-1/2 ${outlineColor}`} 
          style={{ bottom: `${length}px` }}
        ></div>
        <div 
          className={`outline-left absolute w-[1px] h-full top-1/2 -translate-y-1/2 ${outlineColor}`} 
          style={{ left: `${length}px` }}
        ></div>
        <div 
          className={`outline-right absolute w-[1px] h-full top-1/2 -translate-y-1/2 ${outlineColor}`} 
          style={{ right: `${length}px` }}
        ></div>
      </div>
      {children}
    </div>
  );
}
