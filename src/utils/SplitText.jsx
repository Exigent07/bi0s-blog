import { useEffect, useRef } from 'react';
import { gsap } from 'gsap';
import { useGSAP } from '@gsap/react';

export default function SplitText ({
  text = "",
  random = false,
  smallClass = "text-sm",
  mediumClass = "md:text-xl",
  largeClass = "lg:text-3xl",
  wrapperClass = "",
  wrapperStyle = {},
  charStyle = {},
}) {
  const containerRef = useRef(null);
  const previousText = useRef(text);

  const fontClasses = random
    ? ['font-load1', 'font-load2', 'font-load3']
    : ['font-default'];

  const getFontForPosition = (position, offset = 0) => {
    const index = (position + offset) % fontClasses.length;
    return fontClasses[index];
  };

  useGSAP(() => {
    if (!random) return;

    if (text !== previousText.current) {
      const elements = containerRef.current.children;
      const chars = text.split("");

      chars.forEach((_, index) => {
        const element = elements[index];
        if (!element) return;

        fontClasses.forEach((font) => element.classList.remove(font));

        const newFont = getFontForPosition(index);
        element.classList.add(newFont);

        gsap.fromTo(
          element,
          { scale: 0.8 },
          {
            scale: 1,
            duration: 0.3,
            ease: "back.out(1.7)",
          }
        );
      });

      previousText.current = text;
    }
  }, [text]);

  useEffect(() => {
    const elements = containerRef.current.children;
    const chars = text.split("");

    chars.forEach((_, index) => {
      const element = elements[index];
      if (!element) return;
      const initialFont = getFontForPosition(index);
      element.classList.add(initialFont);
    });
  }, []);

  return (
    <div
      ref={containerRef}
      className={`flex items-center justify-center ${wrapperClass}`}
      style={wrapperStyle}
    >
      {text.split("").map((char, index) => (
        <span
          key={index}
          style={charStyle}
          className={`split-char inline-block ${smallClass} ${mediumClass} ${largeClass}`}
        >
          {char === " " ? "\u00A0" : char}
        </span>
      ))}
    </div>
  );
};
