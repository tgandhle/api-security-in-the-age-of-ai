import test from "node:test";
import assert from "node:assert/strict";
import { createAnalytics, CONSENT_KEY, MEASUREMENT_ID } from "./analytics.js";

function fixture({ choice, href, storageBlocked = false } = {}) {
  const values = new Map(choice ? [[CONSENT_KEY, choice]] : []);
  const scripts = [];
  const doc = {
    referrer: "https://www.linkedin.com/feed/?private=value", cookie: "",
    createElement: () => ({}),
    head: { appendChild: (script) => scripts.push(script) }
  };
  const win = {
    location: { href: href || "https://tgandhle.github.io/api-security-in-the-age-of-ai/topics/webhooks/index.html" },
    localStorage: {
      getItem: (key) => {
        if (storageBlocked) throw new Error("Storage blocked");
        return values.get(key) ?? null;
      },
      setItem: (key, value) => {
        if (storageBlocked) throw new Error("Storage blocked");
        values.set(key, value);
      }
    }
  };
  const analytics = createAnalytics(win, doc);
  return { analytics, win, doc, scripts, values,
    commands: () => (win.dataLayer || []).map((args) => [...args]) };
}

test("no Google script or events before permission or after an initial decline", () => {
  for (const choice of [undefined, "denied", "invalid"]) {
    const f = fixture({ choice });
    f.analytics.track("lab_start", "webhooks");
    assert.equal(f.scripts.length, 0);
    assert.deepEqual(f.commands(), []);
  }
});

test("allowing analytics loads the correct property once and remembers permission", () => {
  const f = fixture();
  f.analytics.choose("granted");
  f.analytics.choose("granted");
  assert.equal(f.values.get(CONSENT_KEY), "granted");
  assert.equal(f.scripts.length, 1);
  assert.equal(f.scripts[0].src, "https://www.googletagmanager.com/gtag/js?id=" + MEASUREMENT_ID);
  const config = f.commands().find(([command]) => command === "config");
  assert.equal(config[1], MEASUREMENT_ID);
  assert.equal(config[2].allow_google_signals, false);
  assert.equal(config[2].allow_ad_personalization_signals, false);
});

test("stored permission starts measurement only on the production course", () => {
  for (const href of [
    "http://localhost:4173/topics/webhooks/index.html",
    "file:///C:/course/index.html",
    "https://tgandhle.github.io/another-project/index.html",
    "https://other.example/api-security-in-the-age-of-ai/"
  ]) {
    const f = fixture({ choice: "granted", href });
    assert.equal(f.scripts.length, 0);
  }
  assert.equal(fixture({ choice: "granted" }).scripts.length, 1);
});

test("withdrawal disables Google and stops course events immediately", () => {
  const f = fixture({ choice: "granted" });
  f.analytics.track("lab_start", "webhooks");
  const count = f.commands().length;
  f.doc.cookie = "api_course_ga=value";
  f.analytics.choose("denied");
  f.analytics.track("lesson_complete", "webhooks");
  assert.equal(f.win["ga-disable-" + MEASUREMENT_ID], true);
  assert.equal(f.commands().length, count);
  assert.equal(f.values.get(CONSENT_KEY), "denied");
  assert.match(f.doc.cookie, /api_course_ga=; Max-Age=0/);
});

test("campaign attribution keeps approved labels without arbitrary URL input", () => {
  const f = fixture({ choice: "granted", href:
    "https://tgandhle.github.io/api-security-in-the-age-of-ai/?utm_source=linkedin&utm_medium=organic_social&utm_campaign=course_launch&email=private%40example.com&q=secret#private" });
  const config = f.commands().find(([command]) => command === "config")[2];
  assert.equal(config.campaign_source, "linkedin");
  assert.equal(config.campaign_medium, "organic_social");
  assert.equal(config.campaign_name, "course_launch");
  assert.equal(config.page_location, "https://tgandhle.github.io/api-security-in-the-age-of-ai/");
  assert.equal(config.page_referrer, "https://www.linkedin.com");
  assert.doesNotMatch(JSON.stringify(f.commands()), /secret|private|email=/);
});

test("course events contain only allowed names, lesson slug and destination", () => {
  const f = fixture({ choice: "granted" });
  f.analytics.track("lab_start", "webhooks");
  f.analytics.track("lesson_complete", "webhooks");
  f.analytics.track("search", "private query");
  f.analytics.track("lab_start", "private@example.com");
  const events = f.commands().filter(([command]) => command === "event");
  assert.deepEqual(events, [
    ["event", "lab_start", { lesson_slug: "webhooks", send_to: MEASUREMENT_ID }],
    ["event", "lesson_complete", { lesson_slug: "webhooks", send_to: MEASUREMENT_ID }]
  ]);
});

test("blocked storage does not break the page or load Google before permission", () => {
  const f = fixture({ storageBlocked: true });
  assert.equal(f.scripts.length, 0);
  assert.doesNotThrow(() => f.analytics.choose("granted"));
  assert.equal(f.scripts.length, 1);
  assert.doesNotThrow(() => f.analytics.choose("denied"));
  assert.equal(f.win["ga-disable-" + MEASUREMENT_ID], true);
});
