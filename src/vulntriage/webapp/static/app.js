// Live progress polling for a triage/eval run dossier.
(function () {
  const detail = document.querySelector("[data-run-id]");
  if (!detail) return;
  const runId = detail.getAttribute("data-run-id");
  const kind = detail.getAttribute("data-kind");
  const stateEl = document.querySelector("[data-run-state]");
  const initialState = stateEl ? stateEl.getAttribute("data-run-state") : "";
  if (initialState !== "running" && initialState !== "pending") return;

  const logBody = document.querySelector(".log-body");
  const statusUrl = kind === "triage"
    ? `/runs/${runId}/status`
    : `/runs/${runId}/status`;

  let halted = false;

  async function poll() {
    if (halted) return;
    try {
      const r = await fetch(statusUrl, { cache: "no-store" });
      const s = await r.json();
      render(s);
      if (s.state === "running" || s.state === "pending") {
        setTimeout(poll, 1000);
      } else {
        halted = true;
        // Reload once so the run dossier reflects the final artifacts.
        setTimeout(() => window.location.reload(), 800);
      }
    } catch (e) {
      setTimeout(poll, 2500);
    }
  }

  function render(s) {
    if (logBody && s.progress) {
      logBody.innerHTML = s.progress
        .map((l) => {
          const cls = l.startsWith("[error]") ? "line error" : "line";
          return `<span class="${cls}">${escapeHtml(l)}</span><br>`;
        })
        .join("");
      logBody.scrollTop = logBody.scrollHeight;
    }
    if (stateEl) {
      stateEl.setAttribute("data-run-state", s.state);
      const label = stateEl.querySelector(".stamp-label");
      if (label) label.textContent = stampWord(s.state);
    }
  }

  function stampWord(state) {
    return {
      pending: "Filed",
      running: "In Review",
      done: "Reviewed",
      failed: "Failed",
      interrupted: "Halted",
    }[state] || state;
  }

  function escapeHtml(l) {
    return l.replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    })[c]);
  }

  poll();
})();