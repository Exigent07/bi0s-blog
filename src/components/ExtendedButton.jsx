import Outline from "./Outline";

export default function ExtendedButton ({
  children,
  className = "",
  onClick = () => {}
}) {
  return (
    <Outline>
      <button 
        className={`w-[50px] h-[50px] flex items-center justify-center ${className}`}
        onClick={onClick}
      >
        {children}
      </button>
    </Outline>
  );
}