(() => {
  const storageKey = "api-security-in-the-age-of-ai-progress-v1";

  function loadProgress() {
    try {
      const saved = JSON.parse(window.localStorage.getItem(storageKey));
      if (saved && Array.isArray(saved.completed)) return saved;
    } catch (error) {
      // Progress controls still work for this page if browser storage is unavailable.
    }
    return { completed: [], quizzes: [] };
  }

  function saveProgress(progress) {
    try {
      window.localStorage.setItem(storageKey, JSON.stringify(progress));
    } catch (error) {
      // Do not block learning when browser storage is unavailable.
    }
  }

  let progress = loadProgress();
  if (!Array.isArray(progress.quizzes)) progress.quizzes = [];

  function isComplete(lesson) {
    return progress.completed.includes(lesson);
  }

  function isQuizPassed(quiz) {
    return progress.quizzes.includes(quiz);
  }

  function renderProgress() {
    const lessonCards = [...document.querySelectorAll("[data-course-lesson]")];
    const available = [...new Set(lessonCards.map((card) => card.dataset.courseLesson))];
    const completeCount = available.filter(isComplete).length;
    const percent = available.length ? Math.round((completeCount / available.length) * 100) : 0;
    const quizIds = [...new Set(lessonCards.map((card) => card.dataset.courseQuiz).filter(Boolean))];
    const passedQuizCount = quizIds.filter(isQuizPassed).length;

    lessonCards.forEach((card) => {
      const complete = isComplete(card.dataset.courseLesson);
      card.classList.toggle("is-complete", complete);
      const state = card.querySelector("[data-course-state]");
      if (state) state.textContent = complete ? "Complete" : "Ready";
      const assessment = card.querySelector("[data-course-assessment]");
      if (assessment) assessment.textContent = isQuizPassed(card.dataset.courseQuiz) ? "Quick check passed" : "Quick check required";
    });

    document.querySelectorAll("[data-course-progress]").forEach((element) => {
      element.textContent = `${completeCount} of ${available.length} published lessons complete`;
    });
    document.querySelectorAll("[data-course-progress-bar]").forEach((element) => {
      element.style.width = `${percent}%`;
      // aria-valuenow belongs on the element carrying role="progressbar", not the fill.
      const meter = element.closest('[role="progressbar"]');
      if (meter) meter.setAttribute("aria-valuenow", String(percent));
    });
    document.querySelectorAll("[data-course-assessment-progress]").forEach((element) => {
      element.textContent = `${passedQuizCount} of ${quizIds.length} published quick checks passed`;
    });

    const lesson = document.body.dataset.courseLesson;
    document.querySelectorAll("[data-mark-complete]").forEach((button) => {
      const complete = lesson && isComplete(lesson);
      button.textContent = complete ? "Completed. Mark incomplete" : "Mark lesson complete";
      button.setAttribute("aria-pressed", complete ? "true" : "false");
    });
  }

  function updateLesson(lesson, complete) {
    progress.completed = progress.completed.filter((item) => item !== lesson);
    if (complete) progress.completed.push(lesson);
    saveProgress(progress);
    renderProgress();
  }

  document.addEventListener("click", (event) => {
    const completionButton = event.target.closest("[data-mark-complete]");
    if (completionButton) {
      const lesson = document.body.dataset.courseLesson;
      if (lesson) updateLesson(lesson, !isComplete(lesson));
      return;
    }

    const resetButton = event.target.closest("[data-reset-progress]");
    if (resetButton && window.confirm("Reset saved progress for this course in this browser?")) {
      progress = { completed: [], quizzes: [] };
      saveProgress(progress);
      renderProgress();
      return;
    }

    const checkButton = event.target.closest("[data-check-answer]");
    if (!checkButton) return;

    const quiz = checkButton.closest("[data-quiz]");
    const selected = quiz && quiz.querySelector("input[type=radio]:checked");
    const feedback = quiz && quiz.querySelector("[data-quiz-feedback]");
    if (!quiz || !feedback) return;

    if (!selected) {
      feedback.textContent = "Choose an answer before checking it.";
      feedback.className = "quiz-feedback";
      return;
    }

    const correct = selected.dataset.correct === "true";
    if (correct && quiz.dataset.quizId && !isQuizPassed(quiz.dataset.quizId)) {
      progress.quizzes.push(quiz.dataset.quizId);
      saveProgress(progress);
      renderProgress();
    }
    feedback.textContent = correct ? quiz.dataset.correctFeedback : quiz.dataset.incorrectFeedback;
    feedback.className = correct ? "quiz-feedback is-correct" : "quiz-feedback is-incorrect";
  });


  // ---------------------------------------------------------------------
  // Optional in-browser lab runner.
  //
  // Everything below is progressive enhancement. With JavaScript off, or if
  // the CDN is unreachable, the page is exactly what it was: a published
  // transcript and a link to download the lab and run it with Python. That
  // local run stays the authority; this is for poking at the code.
  //
  // What the integrity attribute covers, honestly: the 18 KB loader only.
  // Pyodide then fetches about 13 MB of WebAssembly and standard library
  // that no browser mechanism can integrity-check. The note rendered next to
  // the button says so.
  // ---------------------------------------------------------------------
  const PYODIDE_BASE = "https://cdn.jsdelivr.net/pyodide/v314.0.7/full/";
  const PYODIDE_SRI =
    "sha384-hYKrcQ7FiKU7f1c92md9N2eh7BoBVX4CPkNDfQyyVclsjZevvDOBUkajGcYk1EF8";
  let pyodideReady = null;

  function injectScript(src, integrity) {
    return new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = src;
      if (integrity) {
        script.integrity = integrity;
        script.crossOrigin = "anonymous";
      }
      script.onload = () => resolve();
      script.onerror = () => reject(new Error("could not load " + src));
      document.head.appendChild(script);
    });
  }

  function labTranscripts() {
    const found = [];
    document.querySelectorAll("pre > code").forEach((code) => {
      const first = (code.textContent || "").split("\n", 1)[0].trim();
      const match = first.match(/^\$ python3 (labs\/(\w+)\.py)$/);
      if (!match) return;
      const link = document.querySelector('a[href$="' + match[1] + '"]');
      if (!link) return;
      found.push({
        pre: code.parentElement,
        file: match[1].split("/").pop(),
        bundle: link.getAttribute("href").replace(/\.py$/, ".lab.js"),
        published: (code.textContent || "").split("\n").slice(1).join("\n").trim()
      });
    });
    return found;
  }

  async function runLab(lab, button, output) {
    function say(text, state) {
      output.textContent = text;
      output.dataset.state = state || "";
    }
    button.disabled = true;
    try {
      say("Loading the lab source ...");
      if (!(window.__labSources && window.__labSources[lab.file])) {
        await injectScript(lab.bundle);
      }
      const source = window.__labSources && window.__labSources[lab.file];
      if (!source) throw new Error("the lab source did not load");

      if (!pyodideReady) {
        say("Downloading Python, about 13 MB, once per visit ...");
        await injectScript(PYODIDE_BASE + "pyodide.js", PYODIDE_SRI);
        pyodideReady = window.loadPyodide({ indexURL: PYODIDE_BASE });
      }
      say("Starting Python ...");
      const py = await pyodideReady;

      say("Running " + lab.file + " ...");
      py.globals.set("__lab_source", source);
      const result = py.runPython([
        "import io, sys",
        "_buf = io.StringIO()",
        "_old = sys.stdout",
        "sys.stdout = _buf",
        "_ns = {'__name__': '__lab__'}",
        "try:",
        "    exec(__lab_source, _ns)",
        "    _rc = _ns['main']()",
        "finally:",
        "    sys.stdout = _old",
        "_buf.getvalue() + '\\n#exit=' + str(_rc)"
      ].join("\n"));

      const split = result.split("\n#exit=");
      const text = split[0].trim();
      const code = split[1];
      const same = text === lab.published;
      say(text + "\n\nexit code " + code
          + "\nmatches the transcript published above: " + same,
          same && code === "0" ? "ok" : "bad");
    } catch (error) {
      say("This did not run: " + (error && error.message ? error.message : error)
          + "\n\nNothing is wrong with the lesson. Download the lab and run it "
          + "with Python, which is what the transcript above came from.", "bad");
      button.disabled = false;
      return;
    }
    button.disabled = false;
  }

  function addLabRunners() {
    labTranscripts().forEach((lab) => {
      const panel = document.createElement("div");
      panel.className = "lab-run";

      const button = document.createElement("button");
      button.className = "button secondary";
      button.type = "button";
      button.textContent = "Run this lab in your browser";

      const note = document.createElement("p");
      note.className = "meta";
      note.textContent =
        "Optional. Downloads about 13 MB of Python from a CDN the first time. "
        + "Only the loader is integrity-checked; the runtime it then fetches "
        + "cannot be. Running the lab on your own machine is the authority.";

      const output = document.createElement("pre");
      output.className = "lab-output";
      output.hidden = true;
      output.setAttribute("aria-live", "polite");
      output.setAttribute("tabindex", "0");

      button.addEventListener("click", () => {
        output.hidden = false;
        runLab(lab, button, output).then(markScrollableRegions);
      });

      panel.appendChild(button);
      panel.appendChild(note);
      panel.appendChild(output);
      lab.pre.insertAdjacentElement("afterend", panel);
    });
  }

  function markScrollableRegions() {
    document.querySelectorAll("pre, .wrap, .diagram").forEach((element) => {
      // A region that scrolls must be reachable by keyboard. WCAG 2.1.1.
      if (element.scrollWidth > element.clientWidth + 1) {
        element.setAttribute("tabindex", "0");
      } else {
        element.removeAttribute("tabindex");
      }
    });
  }

  window.addEventListener("resize", markScrollableRegions);

  renderProgress();
  addLabRunners();
  markScrollableRegions();
})();
