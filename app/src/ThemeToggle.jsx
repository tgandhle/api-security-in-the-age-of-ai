import { useEffect, useState } from "react";

// One key. The inline script prerender.js writes into <head> reads the same
// key before first paint and, if a choice is stored, puts it on <html> as
// data-theme, so the page never flashes the other theme.
//
// Which theme is in effect, in order: the stored choice; otherwise the system
// setting (a system set to light gets light, anything else gets dark). The
// second step is done by theme.css with no script, so this file only has to
// report it.
export const THEME_KEY = "course-theme";
const SYSTEM_LIGHT = "(prefers-color-scheme: light)";

function chosen() {
  const set = document.documentElement.getAttribute("data-theme");
  return set === "light" || set === "dark" ? set : null;
}

function systemTheme() {
  return window.matchMedia && window.matchMedia(SYSTEM_LIGHT).matches
    ? "light" : "dark";
}

// The theme the reader is looking at right now.
function current() {
  return chosen() || systemTheme();
}

// Client only, like search: with JavaScript off there is no switch, and the
// page follows the system setting by CSS alone. A real button whose name says
// what pressing it gives you, with aria-pressed carrying the state. Because
// it is created on the client and not hydrated, its first render already
// shows the theme in effect, including one that came from the system.
export default function ThemeToggle() {
  const [theme, setTheme] = useState(current);
  const light = theme === "light";

  // Until the reader chooses, the page follows the system, so the switch has
  // to follow it too if the system changes while the page is open.
  useEffect(() => {
    if (!window.matchMedia) return undefined;
    const query = window.matchMedia(SYSTEM_LIGHT);
    const follow = () => { if (!chosen()) setTheme(systemTheme()); };
    query.addEventListener("change", follow);
    return () => query.removeEventListener("change", follow);
  }, []);

  function flip() {
    const next = light ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", next);
    try {
      window.localStorage.setItem(THEME_KEY, next);
    } catch {
      // The switch still works for this page if storage is unavailable.
    }
    setTheme(next);
  }

  return (
    <button type="button" className="theme-switch" aria-pressed={light}
            aria-label="Light theme"
            title={light ? "Switch to the dark theme" : "Switch to the light theme"}
            onClick={flip}>
      <span className="theme-opt theme-opt-dark" aria-hidden="true">
        <svg viewBox="0 0 16 16" width="14" height="14" focusable="false">
          <path d="M13.2 9.7A5.6 5.6 0 0 1 6.3 2.8a5.6 5.6 0 1 0 6.9 6.9Z"
                fill="none" stroke="currentColor" strokeWidth="1.4"
                strokeLinejoin="round" />
        </svg>
      </span>
      <span className="theme-opt theme-opt-light" aria-hidden="true">
        <svg viewBox="0 0 16 16" width="14" height="14" focusable="false">
          <circle cx="8" cy="8" r="2.8" fill="none" stroke="currentColor"
                  strokeWidth="1.4" />
          <path d="M8 1.5v1.6M8 12.9v1.6M1.5 8h1.6M12.9 8h1.6M3.4 3.4l1.1 1.1M11.5 11.5l1.1 1.1M12.6 3.4l-1.1 1.1M4.5 11.5l-1.1 1.1"
                fill="none" stroke="currentColor" strokeWidth="1.4"
                strokeLinecap="round" />
        </svg>
      </span>
    </button>
  );
}
