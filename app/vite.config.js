import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Relative base, so a prerendered page still finds its assets when the folder
// is opened from disk rather than served. The published URL structure stays
// exactly what it is today, topics/<slug>/index.html, so no existing link or
// indexed page breaks.
//
// There is no index.html entry because every page is prerendered by
// prerender.js. The client build produces one hashed module, and the manifest
// is how prerender.js learns its name.
export default defineConfig({
  base: "./",
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    manifest: true,
    rollupOptions: { input: "src/entry-client.jsx" }
  }
});
