import Outline from "./Outline";

export default function ExtendedButton ({
  children,
  smallClass = "text-sm",
  mediumClass = "md:text-xl",
  largeClass = "lg:text-3xl",
  wrapperClass = "",
  wrapperStyle = {},
}) {
  return (
    <Outline
      className=""
    >
      <button className="w-[50px] h-[50px] flex items-center justify-center">
        {children}
      </button>
    </Outline>
  );
}