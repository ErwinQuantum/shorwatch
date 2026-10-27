"use strict";
(function () {
  const data = JSON.parse(document.getElementById("shorwatch-data").textContent);
  const findings = data.findings;
  const summary = data.summary;
  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const state = { q: "", severity: "", status: "", role: "", algorithm: "" };

  // Every piece of scanned text goes through textContent: never markup.
  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs || {})) {
      if (value === undefined || value === null || value === false) continue;
      if (key === "text") node.textContent = value;
      else if (key === "class") node.className = value;
      else node.setAttribute(key, value === true ? "" : value);
    }
    for (const child of [].concat(children || [])) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  const plural = (n, one, many) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
  const statusLabel = (s) => (s === "in_transition" ? "in transition" : "vulnerable");
  const fileName = (path) => path.split(/[\\/]/).pop();

  // ---- Theme -----------------------------------------------------------
  const THEMES = ["auto", "light", "dark"];
  const toggle = document.getElementById("theme-toggle");
  function applyTheme(theme) {
    if (theme === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
    toggle.textContent = `Theme: ${theme}`;
  }
  let theme = "auto";
  try { theme = localStorage.getItem("shorwatch-theme") || "auto"; } catch (_) { /* storage blocked */ }
  if (!THEMES.includes(theme)) theme = "auto";
  applyTheme(theme);
  toggle.addEventListener("click", () => {
    theme = THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length];
    applyTheme(theme);
    try { localStorage.setItem("shorwatch-theme", theme); } catch (_) { /* storage blocked */ }
  });

  // ---- Tooltip ---------------------------------------------------------
  const tooltip = document.getElementById("tooltip");
  function showTip(event, text) {
    tooltip.textContent = text;
    tooltip.hidden = false;
    const x = Math.min(event.clientX + 12, window.innerWidth - tooltip.offsetWidth - 8);
    tooltip.style.left = `${x}px`;
    tooltip.style.top = `${event.clientY + 14}px`;
  }
  const hideTip = () => { tooltip.hidden = true; };

  // ---- Overview ----------------------------------------------------------
  document.getElementById("lede").textContent = summary.findings === 0
    ? `No quantum-vulnerable cryptography found in ${plural(summary.files_scanned, "file", "files")}.`
    : `${plural(summary.findings, "finding", "findings")} in ${plural(summary.files_with_findings, "file", "files")}, out of ${plural(summary.files_scanned, "file", "files")} scanned.`;

  const production = summary.findings - summary.in_tests;
  const shor = findings.filter((f) => f.category === "shor").length;
  const kpis = [
    ["Findings", summary.findings, `${plural(summary.files_with_findings, "file", "files")}`],
    ["In production code", production, `${summary.in_tests.toLocaleString()} more in tests`],
    ["Broken by Shor", shor, "need post-quantum algorithms"],
    ["In transition", summary.in_transition, "next to post-quantum code"],
    ["Auto-fixable", summary.fixable, "mechanical fix available"],
  ];
  document.getElementById("kpis").append(...kpis.map(([label, value, hint]) =>
    el("div", { class: "kpi" }, [
      el("p", { class: "kpi-label", text: label }),
      el("p", { class: "kpi-value", text: value.toLocaleString() }),
      el("p", { class: "kpi-hint", text: hint }),
    ])));

  const ready = summary.findings ? Math.round((summary.in_transition / summary.findings) * 100) : 100;
  document.getElementById("readiness").append(
    el("p", { class: "meter-figure" }, [`${ready}%`, el("span", { text: "in transition" })]),
    el("div", {
      class: "meter", role: "meter", "aria-valuemin": "0", "aria-valuemax": "100",
      "aria-valuenow": String(ready), "aria-label": "Findings in transition",
    }, el("div", { class: "meter-fill", style: `width:${ready}%` })),
    el("div", { class: "meter-legend" }, [
      el("span", { text: `${summary.in_transition.toLocaleString()} in transition` }),
      el("span", { text: `${summary.vulnerable.toLocaleString()} vulnerable` }),
    ]),
  );

  const severityCounts = SEVERITIES
    .map((s) => [s, summary.by_severity[s] || 0])
    .filter(([, n]) => n > 0);
  const maxSeverity = Math.max(1, ...severityCounts.map(([, n]) => n));
  const severityBox = document.getElementById("severities");
  if (severityCounts.length === 0) severityBox.append(el("p", { class: "panel-note", text: "Nothing to report." }));
  for (const [severity, n] of severityCounts) {
    const row = el("div", { class: "sev-row" }, [
      el("span", {}, el("span", { class: `badge sev-${severity}`, text: severity })),
      el("div", { class: "sev-track" }, el("div", { class: `sev-fill fill-${severity}`, style: `width:${(n / maxSeverity) * 100}%` })),
      el("span", { class: "sev-count", text: n.toLocaleString() }),
    ]);
    row.addEventListener("mousemove", (e) => showTip(e, `${severity}: ${plural(n, "finding", "findings")}`));
    row.addEventListener("mouseleave", hideTip);
    severityBox.append(row);
  }

  // ---- By algorithm (one hue: magnitude, sorted) ---------------------------
  const byAlgorithm = new Map();
  for (const f of findings) {
    const entry = byAlgorithm.get(f.algorithm) || { total: 0, test: 0 };
    entry.total += 1;
    if (f.role === "test") entry.test += 1;
    byAlgorithm.set(f.algorithm, entry);
  }
  const algorithms = [...byAlgorithm.entries()].sort((a, b) => b[1].total - a[1].total || a[0].localeCompare(b[0]));
  const maxAlgorithm = Math.max(1, ...algorithms.map(([, e]) => e.total));
  const bars = document.getElementById("algorithms");
  const tableBody = document.querySelector("#algorithm-table tbody");
  if (algorithms.length === 0) bars.append(el("p", { class: "panel-note", text: "Nothing to report." }));
  for (const [name, entry] of algorithms) {
    const bar = el("button", { type: "button", class: "bar", "aria-pressed": "false", "data-algorithm": name }, [
      el("span", { class: "bar-label", text: name }),
      el("span", { class: "bar-track" }, el("span", { class: "bar-fill", style: `width:${(entry.total / maxAlgorithm) * 100}%` })),
      el("span", { class: "bar-value", text: entry.total.toLocaleString() }),
    ]);
    bar.addEventListener("click", () => {
      state.algorithm = state.algorithm === name ? "" : name;
      algorithmSelect.value = state.algorithm;
      update();
    });
    bar.addEventListener("mousemove", (e) =>
      showTip(e, `${name}: ${plural(entry.total, "finding", "findings")} (${(entry.total - entry.test).toLocaleString()} production, ${entry.test.toLocaleString()} test)`));
    bar.addEventListener("mouseleave", hideTip);
    bars.append(bar);
    tableBody.append(el("tr", {}, [
      el("th", { scope: "row", text: name }),
      el("td", { text: entry.total.toLocaleString() }),
      el("td", { text: (entry.total - entry.test).toLocaleString() }),
      el("td", { text: entry.test.toLocaleString() }),
    ]));
  }

  // ---- Filters -------------------------------------------------------------
  const severitySelect = document.getElementById("filter-severity");
  for (const [severity] of severityCounts) severitySelect.append(el("option", { value: severity, text: severity }));
  const algorithmSelect = document.getElementById("filter-algorithm");
  for (const [name] of algorithms) algorithmSelect.append(el("option", { value: name, text: name }));

  const controls = {
    q: document.getElementById("filter-q"),
    severity: severitySelect,
    status: document.getElementById("filter-status"),
    role: document.getElementById("filter-role"),
    algorithm: algorithmSelect,
  };
  for (const [key, control] of Object.entries(controls)) {
    control.addEventListener("input", () => { state[key] = control.value.trim(); update(); });
  }
  document.getElementById("filter-reset").addEventListener("click", () => {
    for (const [key, control] of Object.entries(controls)) { control.value = ""; state[key] = ""; }
    update();
  });

  function matches(f) {
    if (state.severity && f.severity !== state.severity) return false;
    if (state.status && f.status !== state.status) return false;
    if (state.role && f.role !== state.role) return false;
    if (state.algorithm && f.algorithm !== state.algorithm) return false;
    if (state.q) {
      const haystack = `${f.path} ${f.algorithm} ${f.rule_id} ${f.title}`.toLowerCase();
      if (!haystack.includes(state.q.toLowerCase())) return false;
    }
    return true;
  }

  // ---- Findings ------------------------------------------------------------
  function codeBlock(f) {
    const start = f.location.start;
    const end = f.location.end;
    const pre = el("pre", { class: "code", "aria-label": `Source around line ${start.line}` });
    f.snippet.lines.forEach((text, i) => {
      const number = f.snippet.first_line + i;
      const hit = number >= start.line && number <= end.line;
      const line = el("span", { class: hit ? "code-line hit" : "code-line" }, el("span", { class: "ln", text: number }));
      if (hit) {
        // Columns are Unicode code points, 1-based.
        const chars = Array.from(text);
        const from = number === start.line ? start.column - 1 : 0;
        const to = number === end.line ? end.column - 1 : chars.length;
        line.append(el("span", {}, [
          chars.slice(0, from).join(""),
          el("mark", { text: chars.slice(from, to).join("") }),
          chars.slice(to).join(""),
        ]));
      } else {
        line.append(el("span", { text }));
      }
      pre.append(line);
    });
    return pre;
  }

  function flowDiagram(f) {
    if (!f.flow || f.flow.length === 0) return null;
    // Steps on the same line ("written here", "passed as x") read as one.
    const merged = [];
    f.flow.forEach((step, i) => {
      const path = step.path || f.path;
      const last = merged[merged.length - 1];
      if (last && last.path === path && last.line === step.location.start.line) last.notes.push(step.note);
      else merged.push({ path, line: step.location.start.line, notes: [step.note], code: f.flow_lines[i] });
    });
    const steps = merged.map((step) => el("li", {}, [
      el("span", { class: "flow-note", text: step.notes.join(", ") }),
      el("span", { class: "flow-where", title: step.path, text: `${fileName(step.path)}:${step.line}` }),
      step.code ? el("code", { class: "flow-code", text: step.code.trim() }) : null,
    ]));
    const use = f.snippet.lines[f.location.start.line - f.snippet.first_line];
    steps.push(el("li", { class: "use" }, [
      el("span", { class: "flow-note", text: `used here: ${f.algorithm}` }),
      el("span", { class: "flow-where", text: `${fileName(f.path)}:${f.location.start.line}` }),
      use ? el("code", { class: "flow-code", text: use.trim() }) : null,
    ]));
    return el("div", { class: "flow" }, [
      el("h3", { text: "How the value gets here" }),
      el("ol", {}, steps),
    ]);
  }

  function findingCard(f) {
    const start = f.location.start;
    return el("article", { class: "finding" }, [
      el("div", { class: "finding-head" }, [
        el("span", { class: `badge sev-${f.severity}`, text: f.severity }),
        el("span", { class: "algorithm", text: f.algorithm }),
        el("span", { class: `pill pill-${f.status === "in_transition" ? "transition" : "vulnerable"}`, text: statusLabel(f.status) }),
        f.role === "test" ? el("span", { class: "pill pill-test", text: "test code" }) : null,
        f.flow && f.flow.length ? el("span", { class: "pill", text: "via data flow" }) : null,
        el("span", { class: "rule", text: f.rule_id }),
        el("span", { class: "where", text: `line ${start.line}, column ${start.column}` }),
      ]),
      el("p", { class: "finding-title", text: f.title }),
      f.detail ? el("p", { class: "detail", text: f.detail }) : null,
      codeBlock(f),
      flowDiagram(f),
      el("div", { class: "explain" }, [
        el("p", {}, [el("strong", { text: "Why it matters. " }), f.message]),
        el("p", {}, [el("strong", { text: "What to do. " }), f.suggestion]),
        f.hybrid_evidence ? el("p", { class: "note" },
          `In transition: post-quantum code at line ${f.hybrid_evidence.location.start.line} (${f.hybrid_evidence.text}).`) : null,
        f.fix ? el("p", { class: "note fix" },
          `Fix: ${f.fix.description}: replace with “${f.fix.replacement}” at line ${f.fix.location.start.line}.`) : null,
        f.references && f.references.length ? el("ul", { class: "refs" }, f.references.map((r) =>
          el("li", {}, el("a", { href: r.url, rel: "noopener noreferrer", target: "_blank", text: r.title })))) : null,
      ]),
    ]);
  }

  const list = document.getElementById("findings");
  const shownCount = document.getElementById("shown-count");
  const SEVERITY_RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));

  function update() {
    for (const bar of bars.querySelectorAll(".bar")) {
      bar.setAttribute("aria-pressed", String(bar.dataset.algorithm === state.algorithm));
    }
    const shown = findings.filter(matches);
    shownCount.textContent = shown.length === findings.length
      ? plural(findings.length, "finding", "findings")
      : `${shown.length.toLocaleString()} of ${plural(findings.length, "finding", "findings")}`;
    list.replaceChildren();
    if (findings.length === 0) {
      list.append(el("div", { class: "empty" }, [
        el("strong", { text: "✓ Nothing quantum-vulnerable found" }),
        "No rule matched in the scanned files.",
      ]));
      return;
    }
    if (shown.length === 0) {
      list.append(el("div", { class: "empty", text: "No finding matches these filters." }));
      return;
    }
    // Files with the most severe findings first, then by path.
    const byFile = new Map();
    for (const f of shown) {
      if (!byFile.has(f.path)) byFile.set(f.path, []);
      byFile.get(f.path).push(f);
    }
    const files = [...byFile.entries()].sort((a, b) => {
      const worst = (fs) => Math.min(...fs.map((f) => SEVERITY_RANK[f.severity] ?? 9));
      return worst(a[1]) - worst(b[1]) || a[0].localeCompare(b[0]);
    });
    const openAll = files.length <= 12;
    for (const [path, fileFindings] of files) {
      const tests = fileFindings.every((f) => f.role === "test");
      list.append(el("details", { class: "file", open: openAll }, [
        el("summary", {}, [
          el("span", { class: "file-path", text: path }),
          tests ? el("span", { class: "pill pill-test", text: "test code" }) : null,
          el("span", { class: "file-count", text: plural(fileFindings.length, "finding", "findings") }),
        ]),
        ...fileFindings.map(findingCard),
      ]));
    }
  }

  update();
})();
