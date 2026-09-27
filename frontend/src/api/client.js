// Talks to the §7 JSON contract frozen by backend/app/api/pipeline.py (see ../../../CLAUDE.md).
// Field shapes aren't enforced here (plain JS, no types) - the backend is the source of
// truth; a renamed/removed field just shows up as `undefined` in the UI, not a build error.

// Empty by default: Vite's dev server proxies /api to the backend (see vite.config.js),
// and the same-origin reverse proxy setup does the same in production. Only needed when
// the frontend is served from a different origin than the API (see docker-compose.yml).
const API_ORIGIN = import.meta.env.VITE_API_BASE_URL ?? "";
const BASE = `${API_ORIGIN}/api/analyses`;

async function handle(res) {
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail ?? detail;
    } catch {
      // response had no JSON body
    }
    throw new Error(detail);
  }
  return res.json();
}

export function listCaptures() {
  return fetch(BASE).then(handle);
}

export function getCapture(captureId) {
  return fetch(`${BASE}/${captureId}`).then(handle);
}

export function uploadCapture(file) {
  const form = new FormData();
  form.append("file", file);
  return fetch(BASE, { method: "POST", body: form }).then(handle);
}
