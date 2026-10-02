// Only the index: slug, module number, lesson number and title. 3.8 KB.
// The lesson bodies are never imported here, because the page is prerendered
// with its own body and React has no reason to carry the other 26.
import index from "../../content/index.json";
export const course = index;
export const lessons = index.lessons;
