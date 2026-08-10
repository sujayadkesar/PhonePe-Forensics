// PhonePe iOS Forensics — UI client-side helpers

// Highlight active nav link
(function () {
  const path = window.location.pathname;
  document.querySelectorAll(".nav-item").forEach((a) => {
    const href = a.getAttribute("href");
    if (href === path || (href !== "/" && path.startsWith(href))) {
      a.classList.add("active");
    }
  });
})();

// Generic table filter (data-filter-input + data-filter-target=tableSelector)
(function () {
  document.querySelectorAll("[data-filter-input]").forEach((input) => {
    const target = document.querySelector(input.getAttribute("data-filter-target"));
    if (!target) return;
    const rows = Array.from(target.querySelectorAll("tbody tr"));
    input.addEventListener("input", () => {
      const q = input.value.trim().toLowerCase();
      let shown = 0;
      rows.forEach((r) => {
        const t = r.textContent.toLowerCase();
        const ok = !q || t.includes(q);
        r.style.display = ok ? "" : "none";
        if (ok) shown++;
      });
      const counter = document.querySelector(input.getAttribute("data-filter-counter"));
      if (counter) counter.textContent = shown + " / " + rows.length;
    });
  });
})();

// Generic select filter (data-filter-select + data-filter-column)
(function () {
  document.querySelectorAll("[data-filter-select]").forEach((sel) => {
    const target = document.querySelector(sel.getAttribute("data-filter-target"));
    if (!target) return;
    const colIdx = parseInt(sel.getAttribute("data-filter-column") || "-1", 10);
    const rows = Array.from(target.querySelectorAll("tbody tr"));
    sel.addEventListener("change", () => {
      const q = sel.value;
      rows.forEach((r) => {
        if (!q) {
          r.style.display = "";
          return;
        }
        const cell = colIdx >= 0 ? r.children[colIdx] : null;
        const text = (cell ? cell.textContent : r.textContent).toLowerCase();
        r.style.display = text.includes(q.toLowerCase()) ? "" : "none";
      });
    });
  });
})();

// Async export trigger
(function () {
  const btn = document.querySelector("[data-export]");
  if (!btn) return;
  btn.addEventListener("click", async () => {
    btn.textContent = "Exporting…";
    btn.disabled = true;
    try {
      const r = await fetch("/api/export", { method: "POST" });
      const data = await r.json();
      btn.textContent = "Export complete (" + data.files.length + " files)";
      setTimeout(() => window.location.reload(), 800);
    } catch (e) {
      btn.textContent = "Export failed";
    }
  });
})();

// Inline blob viewer for transactions
(function () {
  const buttons = document.querySelectorAll("[data-blob-id]");
  buttons.forEach((b) => {
    b.addEventListener("click", async (ev) => {
      ev.preventDefault();
      const id = b.getAttribute("data-blob-id");
      const target = document.querySelector(b.getAttribute("data-blob-target"));
      if (!target) return;
      target.textContent = "Loading...";
      try {
        const r = await fetch("/api/blob?id=" + encodeURIComponent(id));
        const j = await r.json();
        target.textContent = JSON.stringify(j, null, 2);
      } catch (e) {
        target.textContent = "Error: " + e.message;
      }
    });
  });
})();
