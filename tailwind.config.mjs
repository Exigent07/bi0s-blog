/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        text: "var(--color-text)",
        muted: "var(--color-muted)",
        border: "var(--color-border)",
        background: "var(--color-solid-bg)",
        "highlight-bg": "var(--color-bg)",

        subtle: "var(--color-subtle)",
        deep: "var(--color-deep)",
        mid: "var(--color-mid)",
        shadow: "var(--color-shadow)",
      },
      fontFamily: {
        primary: ["Lato", "sans-serif"],
        heading: ["Raleway", "sans-serif"],
        body: ["Poppins", "sans-serif"],
        highlight: ["Lora", "serif"],
        meta: ["Quicksand", "sans-serif"],
      },
    },
  },
  plugins: [],
  darkMode: "class",
};
