import { useEffect, useState } from "react";
import { PARTS } from "./parts.js";

const storageKey = "api-security-in-the-age-of-ai-progress-v1";

function readCompleted() {
  try {
    const saved = JSON.parse(window.localStorage.getItem(storageKey));
    if (saved && Array.isArray(saved.completed)) return saved.completed;
  } catch {
    // The rail renders without ticks if browser storage is unavailable.
  }
  return [];
}

// The lesson list, on every lesson page. This is the thing the static site
// never had: a reader finishing one module could not reach the next without
// going back to the dashboard. It is prerendered, so it works with JavaScript
// off too.
//
// Completion ticks are read after the first render, not during it. The
// prerendered rail has none, so reading storage during hydration would give
// React markup that differs from the server's for any reader with progress.
// assets/course.js owns the stored progress; this only reads it again after
// the two buttons that change it are pressed.
//
// On a narrow screen the list sits behind one button that names the lesson
// you are on. The button only appears when JavaScript is running (the "js"
// class on <html>); without it the list is a bounded scrolling block, as it
// was before.
export default function Sidebar({ lessons, current, up, completed }) {
  const [done, setDone] = useState(completed || []);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    setDone(readCompleted());
    function onClick(event) {
      const target = event.target;
      if (target && target.closest &&
          target.closest("[data-mark-complete], [data-reset-progress]")) {
        window.setTimeout(() => setDone(readCompleted()), 0);
      }
    }
    document.addEventListener("click", onClick);
    return () => document.removeEventListener("click", onClick);
  }, []);

  const here = lessons.find((lesson) => lesson.slug === current);
  return (
    <nav className="course-rail" aria-label="Lessons">
      <button type="button" className="rail-toggle" aria-expanded={open}
              aria-controls="rail-list" onClick={() => setOpen(!open)}>
        <span className="rail-toggle-label">Modules</span>
        {here ? (
          <span className="rail-toggle-here">
            <span className="rail-num">{here.module}</span>
            {here.title}
          </span>
        ) : null}
        <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"
             focusable="false">
          <path d="m4 6 4 4 4-4" fill="none" stroke="currentColor"
                strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>
      <p className="rail-title">Modules</p>
      <div className="rail-list" id="rail-list" data-open={open ? "true" : "false"}>
        {PARTS.map((part) => {
          const mine = lessons.filter(
            (l) => l.module >= part.from && l.module <= part.to);
          if (!mine.length) return null;
          return (
            <div className="rail-group" key={part.name}>
              <p className="rail-part">{part.name}</p>
              <ol>
                {mine.map((lesson) => {
                  const isHere = lesson.slug === current;
                  const isDone = done.indexOf(lesson.slug) !== -1;
                  const cls = [isHere ? "here" : "", isDone ? "is-done" : ""]
                    .filter(Boolean).join(" ");
                  return (
                    <li key={lesson.slug} className={cls || undefined}>
                      <a
                        href={up + "topics/" + lesson.slug + "/index.html"}
                        aria-current={isHere ? "page" : undefined}
                      >
                        <span className="rail-num">{lesson.module}</span>
                        <span className="rail-name">{lesson.title}</span>
                        {isDone ? (
                          <span className="rail-done">
                            <svg viewBox="0 0 16 16" width="14" height="14"
                                 aria-hidden="true" focusable="false">
                              <path d="m3.5 8.3 3 3 6-6.5" fill="none"
                                    stroke="currentColor" strokeWidth="1.8"
                                    strokeLinecap="round" strokeLinejoin="round" />
                            </svg>
                            <span className="visually-hidden">completed</span>
                          </span>
                        ) : null}
                      </a>
                    </li>
                  );
                })}
              </ol>
            </div>
          );
        })}
      </div>
    </nav>
  );
}
