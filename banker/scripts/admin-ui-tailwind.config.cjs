const path = require("node:path");

const rootDir = path.resolve(__dirname, "..");

module.exports = {
  darkMode: "class",
  content: [
    path.join(rootDir, ".admin-ui.html")
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          50: "#eff6ff",
          100: "#dbeafe",
          200: "#bfdbfe",
          300: "#93c5fd",
          400: "#60a5fa",
          500: "#3b82f6",
          600: "#2563eb",
          700: "#1d4ed8"
        },
        surface: {
          panel: "#ffffff",
          soft: "#f8fafc",
          dark: "#0f172a"
        },
        border: {
          soft: "#e2e8f0",
          strong: "#cbd5e1",
          dark: "#334155"
        },
        text: {
          strong: "#0f172a",
          dark: "#f8fbff"
        }
      },
      borderRadius: {
        field: "0.5rem",
        control: "0.75rem",
        panel: "1.5rem",
        pill: "9999px"
      },
      boxShadow: {
        "ui-brand": "0 10px 22px rgba(37,99,235,0.16)",
        "ui-brand-hover": "0 14px 28px rgba(37,99,235,0.18)",
        "ui-brand-soft": "0 6px 16px rgba(59,130,246,0.08)",
        "ui-card-hover": "0 18px 36px rgba(15,23,42,0.07)",
        "ui-card-hover-dark": "0 16px 32px rgba(2,6,23,0.34)",
        "ui-surface": "0 0 0 1px rgba(226,232,240,0.92),0 10px 22px rgba(15,23,42,0.05)",
        "ui-surface-dark": "0 0 0 1px rgba(51,65,85,0.88),0 10px 22px rgba(2,6,23,0.3)",
        "ui-surface-hover": "0 0 0 1px rgba(203,213,225,0.98),0 14px 28px rgba(15,23,42,0.08)",
        "ui-surface-hover-dark": "0 0 0 1px rgba(71,85,105,0.92),0 16px 30px rgba(2,6,23,0.38)"
      },
      transitionTimingFunction: {
        "out-expo": "cubic-bezier(0.22,1,0.36,1)"
      },
      transitionDuration: {
        ui: "220ms",
        "ui-slow": "260ms"
      }
    }
  }
};
