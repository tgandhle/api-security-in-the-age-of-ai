// The lessons come from content/, which tools/extract_lessons.py generates
// from the published HTML and verifies byte for byte. Nothing here retypes
// lesson text; blocks carry the original markup.
const lessonFiles = import.meta.glob("../../content/lessons/*.json", {
  eager: true, import: "default"
});
import index from "../../content/index.json";

const bySlug = {};
for (const path in lessonFiles) {
  const record = lessonFiles[path];
  bySlug[record.slug] = record;
}

export const course = index;
export const lessons = index.lessons.map((entry) => ({
  ...entry,
  record: bySlug[entry.slug]
}));
export function lessonBySlug(slug) {
  return lessons.find((lesson) => lesson.slug === slug) || null;
}
