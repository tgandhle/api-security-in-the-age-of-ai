import { useEffect, useState } from 'react'
import './course.css'

const storageKey = 'api-security-react-poc-progress-v1'

const lesson = {
  title: 'API keys',
  objective: 'Find an API key leak in a request log, explain why someone can reuse the key, and test both prevention and recovery.',
  attack: 'A caller puts an API key in a URL query string. The receiver records that target. Anyone who can read the log can extract the key and reuse it on another request.',
  control: ['Reject query credentials, including empty or duplicate inputs.', 'Read one credential from the agreed header and reject missing or unknown values.', 'Check that the server-side credential record is active, then apply authorization for the action and resource.', 'Log the route label, decision, and non-secret record identifier. Never log raw credentials.'],
  lab: ['1. legitimate query request: accept', '2. query log scanner findings: 1', '3. attacker reuses logged key: accept', '4. query credential after fix: reject: query credential', '9. stolen key after revocation: reject: invalid credential', '17. empty query credential: reject: query credential', 'all lab checks passed'],
  checklist: ['Credentials stay out of URLs and telemetry.', 'Exposed keys can be revoked everywhere.', 'Key validation is followed by permission checks.'],
}

function readProgress() {
  try {
    const saved = JSON.parse(window.localStorage.getItem(storageKey))
    if (saved && typeof saved === 'object') return saved
  } catch {
    // The proof remains usable if browser storage is unavailable.
  }
  return { complete: false, quizPassed: false }
}

export default function CourseProof() {
  const [progress, setProgress] = useState(readProgress)
  const [answer, setAnswer] = useState('')
  const [feedback, setFeedback] = useState('')

  useEffect(() => {
    window.localStorage.setItem(storageKey, JSON.stringify(progress))
  }, [progress])

  function checkAnswer() {
    if (!answer) return setFeedback('Choose an answer before checking it.')
    if (answer === 'revoke') {
      setProgress((current) => ({ ...current, quizPassed: true }))
      return setFeedback('Correct. Preventing new log exposure is important, but revocation stops reuse of a key that was already stolen.')
    }
    return setFeedback('Not quite. A header-only rule prevents a new query-string leak. It does not invalidate a key that an attacker already copied.')
  }

  return <>
    <a className="skip-link" href="#main-content">Skip to lesson content</a>
    <header className="site-header"><a className="brand" href="https://tgandhle.github.io/api-security-in-the-age-of-ai/">API Security in the Age of AI</a><span className="proof-label">React proof</span></header>
    <main id="main-content">
      <section className="hero" aria-labelledby="lesson-title">
        <p className="eyebrow">Part 1: Proving who is calling, Module 1</p><h1 id="lesson-title">{lesson.title}</h1><p className="objective"><strong>Objective.</strong> {lesson.objective}</p>
        <div className="progress-card" aria-label="Lesson completion"><div><strong>Module 1 proof</strong><span>{progress.quizPassed ? 'Quick check passed' : 'Quick check required'}</span></div><button type="button" onClick={() => setProgress((current) => ({ ...current, complete: !current.complete }))} aria-pressed={progress.complete}>{progress.complete ? 'Completed. Mark incomplete' : 'Mark lesson complete'}</button></div>
      </section>
      <nav className="lesson-nav" aria-label="Lesson sections"><a href="#attack">Attack</a><a href="#control">Control</a><a href="#lab">Lab</a><a href="#check">Quick check</a><a href="#reference">Reference</a></nav>
      <section id="attack"><p className="eyebrow">1. The attack</p><h2>A credential in a log becomes a credential for the attacker</h2><p>{lesson.attack}</p><div className="comparison" role="group" aria-label="API key outcomes"><div><strong>Query key and raw log</strong><span>Leaked keys can be reused.</span></div><div><strong>Header key and safe log</strong><span>New query-string leaks are rejected.</span></div><div><strong>After revocation</strong><span>The old key is inactive.</span></div></div></section>
      <section id="control"><p className="eyebrow">3. The control</p><h2>Separate prevention from recovery</h2><ol>{lesson.control.map((item) => <li key={item}>{item}</li>)}</ol><aside><strong>What this proves:</strong> a request supplied a credential that the receiver currently accepts. It does not prove the original application sent it or that the operation is authorized.</aside></section>
      <section id="lab"><p className="eyebrow">7. Lab</p><h2>Run the existing Python lab</h2><p>From the repository root, run <code>python3 labs/api_keys_lab.py</code>. The proof keeps the lab outside the browser and uses its actual recorded output.</p><pre><code>{lesson.lab.join('\n')}</code></pre></section>
      <section id="check" className="quiz"><p className="eyebrow">Quick check</p><h2>Recover from a leaked key</h2><fieldset><legend>A key was already copied from an old request log. Which action stops reuse of that copied value?</legend><label><input type="radio" name="recovery" value="header" checked={answer === 'header'} onChange={(event) => setAnswer(event.target.value)} /> Move the key to a request header.</label><label><input type="radio" name="recovery" value="revoke" checked={answer === 'revoke'} onChange={(event) => setAnswer(event.target.value)} /> Revoke the exposed key and issue a replacement.</label><label><input type="radio" name="recovery" value="length" checked={answer === 'length'} onChange={(event) => setAnswer(event.target.value)} /> Make future keys longer.</label></fieldset><button type="button" onClick={checkAnswer}>Check answer</button><p className="feedback" aria-live="polite">{feedback}</p></section>
      <section id="reference"><p className="eyebrow">Reference</p><h2>Review checklist</h2><ul>{lesson.checklist.map((item) => <li key={item}>{item}</li>)}</ul><p>Read the complete static lesson for all controls, checklist items, and sources: <a href="https://tgandhle.github.io/api-security-in-the-age-of-ai/topics/api-keys/">API keys</a>.</p></section>
    </main>
  </>
}
