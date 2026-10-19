import { useState } from "react";

export default function AnalyticsPreferences({ analytics }) {
  const [choice, setChoice] = useState(analytics.getChoice);
  function choose(value) {
    analytics.choose(value);
    setChoice(value);
  }
  return (
    <details open={true}>
      <summary>Analytics preferences</summary>
      <p className="prose">
        With your permission, this course uses Google Analytics to measure page
        visits, traffic sources, lesson completion and lab starts. Google receives
        usage and device information and uses cookies to recognize return visits.
        Search text, quiz answers, checklist answers and lab output are not sent
        by the course analytics code. You can decline and keep using the course,
        or change your choice here at any time.
        {" "}<a href="https://policies.google.com/technologies/partner-sites">How Google uses this data</a>.
      </p>
      <p>
        <button type="button" className="button secondary"
                aria-pressed={choice === "granted"}
                onClick={() => choose("granted")}>Allow analytics</button>{" "}
        <button type="button" className="button secondary"
                aria-pressed={choice === "denied"}
                onClick={() => choose("denied")}>Decline analytics</button>
      </p>
      <p role="status">
        {choice === "granted" ? "Analytics allowed. You can withdraw permission here."
          : choice === "denied" ? "Analytics declined. No further course analytics will be sent."
          : "Analytics is off until you allow it. Your choice is saved in this browser."}
      </p>
    </details>
  );
}
