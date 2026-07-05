// ---- Intake-form helpers: model picker, local-only, ensemble ---------------- //
window.VulnTriage = (function () {
  // One datalist is shared by the primary row and every ensemble row.
  function datalist() { return document.getElementById("models-dl"); }

  async function fetchModels(provider) {
    try {
      const r = await fetch(`/models?provider=${encodeURIComponent(provider)}`, { cache: "no-store" });
      const j = await r.json();
      return Array.isArray(j.models) ? j.models : [];
    } catch (e) { return []; }
  }

  function setOptions(models) {
    const dl = datalist();
    if (!dl) return;
    dl.innerHTML = "";
    for (const m of models.slice(0, 200)) {
      const o = document.createElement("option");
      o.value = m;
      dl.appendChild(o);
    }
  }

  async function refreshModels(selectEl) {
    if (!selectEl) return;
    setOptions(await fetchModels(selectEl.value));
  }

  function onLocalOnlyToggle(checked) {
    const selects = document.querySelectorAll("select[name=provider]");
    selects.forEach((sel) => {
      Array.from(sel.options).forEach((o) => {
        o.hidden = checked && !o.dataset.local;
      });
      if (checked && sel.selectedOptions[0] && sel.selectedOptions[0].hidden) {
        const firstVisible = Array.from(sel.options).find((o) => !o.hidden);
        if (firstVisible) { sel.value = firstVisible.value; }
        refreshModels(sel);
      }
    });
  }

  let ensembleIdx = 0;

  function addEnsembleRow() {
    const container = document.getElementById("ensemble-rows");
    if (!container) return;
    const row = document.createElement("div");
    row.className = "row model-row";
    row.dataset.modelRow = "";
    const n = ensembleIdx++;
    // Provider <select> mirroring the primary.
    const pSelect = document.createElement("select");
    pSelect.name = "ensemble_provider";
    const primary = document.querySelector("select[name=provider]");
    if (primary) {
      Array.from(primary.options).forEach((o) => {
        const c = o.cloneNode(true);
        pSelect.appendChild(c);
      });
    }
    pSelect.addEventListener("change", () => refreshModels(pSelect));
    const pLabel = document.createElement("label");
    pLabel.textContent = `Scoring model provider #${n + 2}`;
    row.appendChild(pLabel);
    row.appendChild(pSelect);
    // Model input + remove button.
    const mRow = document.createElement("div");
    mRow.style.marginTop = "6px";
    const mInput = document.createElement("input");
    mInput.type = "text";
    mInput.name = "ensemble_model";
    mInput.setAttribute("list", "models-dl");
    mInput.setAttribute("autocomplete", "off");
    mInput.placeholder = "model name";
    const rm = document.createElement("button");
    rm.type = "button";
    rm.className = "btn ghost";
    rm.textContent = "remove";
    rm.style.marginLeft = "8px";
    rm.addEventListener("click", () => { row.remove(); });
    mRow.appendChild(mInput);
    mRow.appendChild(rm);
    row.appendChild(mRow);
    container.appendChild(row);
    // Apply current local-only gating to the new select.
    const cb = document.getElementById("local_only");
    if (cb && cb.checked) onLocalOnlyToggle(true);
  }

  function onEnsembleToggle(checked) {
    const fields = document.getElementById("ensemble-rows");
    const wrap = document.getElementById("ensemble-fields");
    if (wrap) wrap.style.display = checked ? "" : "none";
    if (!checked) {
      // Clear any extra rows so a single-model POST is identical to today.
      if (fields) fields.innerHTML = "";
      const q = document.querySelector("input[name=quorum]");
      if (q) q.value = "";
    }
  }

  return {
    refreshModels,
    onLocalOnlyToggle,
    addEnsembleRow,
    onEnsembleToggle,
  };
})();

// ---- Live progress polling for a triage/eval run dossier ------------------- //
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