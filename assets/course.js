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
      element.setAttribute("aria-valuenow", String(percent));
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

  renderProgress();
})();
