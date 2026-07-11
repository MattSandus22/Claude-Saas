import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      // Chart + status colors use the validated data-viz palette (see
      // scripts/validate_palette.js). Status hues are the fixed status palette
      // (good/warning/serious/critical); brand is validated categorical blue.
      colors: {
        bg: "#0a0e14",
        surface: "#111722",
        "surface-2": "#161d2b",
        border: "#1f2937",
        muted: "#898781",
        brand: "#3987e5",
        "brand-dark": "#1c5cab",
        ok: "#0ca30c", // status: good
        warn: "#fab219", // status: warning (medium severity)
        danger: "#ec835a", // status: serious (high severity)
        critical: "#d03b3b", // status: critical
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};
export default config;
