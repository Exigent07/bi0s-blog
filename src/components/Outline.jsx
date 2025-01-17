export default function Outline({
  children, 
  className = "w-fit h-fit",
  style = {},
}) {
  return (
    <div 
      className={`outlinedElement relative ${className}`} 
      style={style}
    >
      <div className="outline-container h-full w-full pointer-events-none absolute inset-0">
        <div className="outline-top absolute -top-0.5 h-[1px] w-[125%] left-1/2 -translate-x-1/2 bg-deep"></div>
        <div className="outline-bottom absolute -bottom-0.5 h-[1px] w-[125%] left-1/2 -translate-x-1/2 bg-deep"></div>
        <div className="outline-left absolute -left-0.5 w-[1px] h-[125%] top-1/2 -translate-y-1/2 bg-deep"></div>
        <div className="outline-right absolute -right-0.5 w-[1px] h-[125%] top-1/2 -translate-y-1/2 bg-deep"></div>
      </div>
      {children}
    </div>
  );
}