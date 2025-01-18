"use client"

import { useEffect, useRef } from 'react';
import { gsap } from 'gsap';
import { useGSAP } from '@gsap/react';

export default function SplitText ({
  text = "",
  className = "",
  wrapperClass = "",
  wrapperStyle = {},
  charStyle = {},
}) {
  return (
    <div
      className={`flex items-center justify-center ${wrapperClass}`}
      style={wrapperStyle}
    >
      {text.split("").map((char, index) => (
        <span
          key={index}
          style={charStyle}
          className={`split-char inline-block ${className}`}
        >
          {char === " " ? "\u00A0" : char}
        </span>
      ))}
    </div>
  );
};
