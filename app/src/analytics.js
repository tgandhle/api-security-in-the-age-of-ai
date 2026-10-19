export const MEASUREMENT_ID = "G-HYZ70HJ8M9";
export const CONSENT_KEY = "api-security-course-analytics-v1";
const BASE = "/api-security-in-the-age-of-ai/";

// This client belongs only to the published course. Downloads and previews
// never send visits to the production property.
export function createAnalytics(win = window, doc = document) {
  const url = new URL(win.location.href);
  const eligible = url.protocol === "https:" &&
    url.hostname === "tgandhle.github.io" && url.pathname.startsWith(BASE);
  let choice = null;
  try { choice = win.localStorage.getItem(CONSENT_KEY); } catch {
    // A choice still works for this page when storage is unavailable.
  }
  if (choice !== "granted" && choice !== "denied") choice = null;
  let started = false;
  let enabled = false;

  function start() {
    enabled = eligible && choice === "granted";
    win["ga-disable-" + MEASUREMENT_ID] = !enabled;
    if (!enabled || started) return;
    started = true;
    win.dataLayer = win.dataLayer || [];
    win.gtag = function () { win.dataLayer.push(arguments); };
    win.gtag("consent", "default", {
      analytics_storage: "granted", ad_storage: "denied",
      ad_user_data: "denied", ad_personalization: "denied"
    });
    win.gtag("js", new Date());
    // Drop fragments and arbitrary query parameters. Campaign labels are
    // explicit fields, so search text and other URL input are not recorded.
    const config = {
      page_location: url.origin + url.pathname,
      page_referrer: doc.referrer ? new URL(doc.referrer).origin : "",
      allow_google_signals: false,
      allow_ad_personalization_signals: false,
      cookie_domain: "none", cookie_path: BASE, cookie_prefix: "api_course"
    };
    for (const [param, field] of [
      ["utm_source", "campaign_source"], ["utm_medium", "campaign_medium"],
      ["utm_campaign", "campaign_name"]
    ]) {
      const value = url.searchParams.get(param);
      if (value && /^[a-z0-9_-]{1,80}$/i.test(value)) config[field] = value;
    }
    win.gtag("config", MEASUREMENT_ID, config);
    const script = doc.createElement("script");
    script.async = true;
    script.src = "https://www.googletagmanager.com/gtag/js?id=" + MEASUREMENT_ID;
    doc.head.appendChild(script);
  }

  start();
  return {
    getChoice: () => choice,
    choose(value) {
      if (value !== "granted" && value !== "denied") return;
      choice = value;
      try { win.localStorage.setItem(CONSENT_KEY, value); } catch {
        // Reading the course must not depend on browser storage.
      }
      start();
      if (value === "denied") {
        for (const cookie of doc.cookie.split(";")) {
          const name = cookie.split("=")[0].trim();
          if (name.startsWith("api_course_ga")) {
            doc.cookie = name + "=; Max-Age=0; Path=" + BASE + "; Secure; SameSite=Lax";
          }
        }
      }
    },
    track(event, lesson) {
      if (!enabled || !["lesson_complete", "lab_start"].includes(event)) return;
      if (!/^[a-z0-9-]+$/.test(lesson || "")) return;
      win.gtag("event", event, { lesson_slug: lesson, send_to: MEASUREMENT_ID });
    }
  };
}
