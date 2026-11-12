/* Dashboard charts. Attacker strings only ever reach Chart.js labels (drawn on
   canvas) or textContent — never innerHTML — so they cannot execute. */
(function () {
  "use strict";

  // ---------- auto refresh (per-viewer preference) ----------
  const toggle = document.getElementById("auto-refresh");
  const seconds = parseInt(document.body.dataset.refresh || "30", 10);
  let pref = false;
  try { pref = localStorage.getItem("hp-auto-refresh") === "1"; } catch (e) { /* storage blocked */ }
  if (toggle) {
    toggle.checked = pref;
    toggle.addEventListener("change", () => {
      try { localStorage.setItem("hp-auto-refresh", toggle.checked ? "1" : "0"); } catch (e) { /* ignore */ }
      if (toggle.checked) schedule();
    });
  }
  function schedule() {
    setTimeout(() => { if (toggle && toggle.checked) location.reload(); }, seconds * 1000);
  }
  if (pref) schedule();

  // ---------- charts ----------
  const dataEl = document.getElementById("chart-data");
  if (!dataEl || typeof Chart === "undefined") return;
  const data = JSON.parse(dataEl.textContent);

  const css = getComputedStyle(document.documentElement);
  const v = (name) => css.getPropertyValue(name).trim();
  const C1 = v("--chart-1"), C2 = v("--chart-2"), GRID = v("--chart-grid"), TEXT = v("--muted");

  // The page is lang="ar"; keep chart numbers in the same Latin digits as the KPI tiles.
  Chart.defaults.locale = "en-US";
  Chart.defaults.font.family = v("--font");
  Chart.defaults.color = TEXT;
  Chart.defaults.plugins.legend.labels.boxWidth = 12;

  const axis = { grid: { color: GRID }, ticks: { color: TEXT }, border: { display: false } };

  // timeline
  const tlCanvas = document.getElementById("timelineChart");
  let timeline;
  if (tlCanvas) {
    timeline = new Chart(tlCanvas, {
      type: "line",
      data: {
        labels: data.timeline.labels,
        datasets: [
          { label: "محاولات", data: data.timeline.attempts, borderColor: C1, backgroundColor: C1 + "22",
            fill: true, tension: 0.3, pointRadius: 0, borderWidth: 2 },
          { label: "دخول ناجح", data: data.timeline.successes, borderColor: C2, backgroundColor: C2,
            tension: 0.3, pointRadius: 0, borderWidth: 2 },
        ],
      },
      options: {
        maintainAspectRatio: false, interaction: { mode: "index", intersect: false },
        scales: { x: { ...axis, reverse: false }, y: { ...axis, beginAtZero: true, ticks: { ...axis.ticks, precision: 0 } } },
      },
    });

    document.querySelectorAll(".seg button[data-hours]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        document.querySelectorAll(".seg button").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        try {
          const res = await fetch("/api/timeline?hours=" + encodeURIComponent(btn.dataset.hours), { credentials: "same-origin" });
          const t = await res.json();
          timeline.data.labels = t.labels;
          timeline.data.datasets[0].data = t.attempts;
          timeline.data.datasets[1].data = t.successes;
          timeline.update();
        } catch (e) { console.error(e); }
      });
    });
  }

  const MAX_LABEL = 18;

  // Horizontal bar chart. Long labels (attacker passwords can be anything) are
  // truncated on the axis; the tooltip always shows the full value.
  function hbar(id, rows, color, footer) {
    const el = document.getElementById(id);
    if (!el || !rows.length) return;
    new Chart(el, {
      type: "bar",
      data: { labels: rows.map((r) => r.value === "" ? "(فارغ)" : r.value),
              datasets: [{ data: rows.map((r) => r.count), backgroundColor: color, borderRadius: 4, maxBarThickness: 22 }] },
      options: {
        indexAxis: "y", maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: footer ? { footer: (items) => footer(rows[items[0].dataIndex]) } : {} },
        },
        scales: { x: { ...axis, beginAtZero: true, ticks: { ...axis.ticks, precision: 0 } },
                  y: { ...axis, grid: { display: false }, position: "right",
                       ticks: { color: v("--text"), font: { family: v("--mono"), size: 12 },
                                callback(value) {
                                  const label = String(this.getLabelForValue(value));
                                  // trailing LRM keeps the ellipsis on the right in the RTL canvas
                                  return label.length > MAX_LABEL ? label.slice(0, MAX_LABEL - 1) + "…‎" : label;
                                } } } },
      },
    });
  }
  hbar("passwordsChart", data.passwords, C2);
  hbar("usernamesChart", data.usernames, C1);

  // behaviour tags; the MITRE ATT&CK technique id is shown on hover
  hbar("tagsChart", data.tags.map((t) => ({ value: t.tag, count: t.count, technique: t.technique })),
       v("--warn"), (row) => (row.technique ? "MITRE ATT&CK: " + row.technique : ""));
})();
