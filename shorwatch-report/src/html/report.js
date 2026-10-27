"use strict";
(function () {
  const data = JSON.parse(document.getElementById("shorwatch-data").textContent);
  const allFindings = data.findings;
  const projects = data.projects || [];
  const multi = projects.length > 1;
  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const SEVERITY_RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));
  const filters = { q: "", severity: "", status: "", role: "", algorithm: "" };
  // `null`: every project; otherwise an index into `projects`.
  let scope = null;

  // Every piece of scanned text goes through textContent: never markup.
  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs || {})) {
      if (value === undefined || value === null || value === false) continue;
      if (key === "text") node.textContent = value;
      else if (key === "class") node.className = value;
      else node.setAttribute(key, value === true ? "" : value);
    }
    for (const child of [].concat(children || []).flat(Infinity)) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  const plural = (n, one, many) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
  const statusLabel = (s) => (s === "in_transition" ? "in transition" : "vulnerable");
  const fileName = (path) => path.split(/[\\/]/).pop();
  const inScope = (f, index) => index === null || f.project === index;

  /** The counts the overview shows, for some findings. */
  function summarize(findings, filesScanned) {
    const bySeverity = {};
    for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    return {
      findings: findings.length,
      files_scanned: filesScanned,
      files_with_findings: new Set(findings.map((f) => f.path)).size,
      in_tests: findings.filter((f) => f.role === "test").length,
      in_transition: findings.filter((f) => f.status === "in_transition").length,
      vulnerable: findings.filter((f) => f.status !== "in_transition").length,
      fixable: findings.filter((f) => f.fix).length,
      by_severity: bySeverity,
    };
  }

  /** Algorithms by count, most frequent first. */
  function algorithmCounts(findings) {
    const counts = new Map();
    for (const f of findings) {
      const entry = counts.get(f.algorithm) || { total: 0, test: 0 };
      entry.total += 1;
      if (f.role === "test") entry.test += 1;
      counts.set(f.algorithm, entry);
    }
    return [...counts.entries()].sort((a, b) => b[1].total - a[1].total || a[0].localeCompare(b[0]));
  }

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
  function withTip(node, text) {
    node.addEventListener("mousemove", (e) => showTip(e, text));
    node.addEventListener("mouseleave", hideTip);
    return node;
  }

  // ---- Projects: tabs and the index ---------------------------------------
  const projectFindings = projects.map((_, i) => allFindings.filter((f) => f.project === i));
  // Projects with the most severe findings first, clean ones last.
  const projectOrder = projects.map((_, i) => i).sort((a, b) => {
    const worst = (i) => Math.min(9, ...projectFindings[i].map((f) => SEVERITY_RANK[f.severity] ?? 9));
    return worst(a) - worst(b) || projectFindings[b].length - projectFindings[a].length
      || projects[a].name.localeCompare(projects[b].name);
  });
  const tabs = document.getElementById("tabs");

  function tab(label, count, index) {
    const button = el("button", { type: "button", class: "tab", role: "tab", "aria-selected": "false" }, [
      label, el("span", { class: "tab-count", text: count.toLocaleString() }),
    ]);
    button.addEventListener("click", () => select(index));
    button.dataset.scope = index === null ? "all" : String(index);
    return button;
  }

  function severityBadges(findings) {
    const counts = SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]).filter(([, n]) => n);
    return el("div", { class: "card-badges" },
      counts.map(([s, n]) => el("span", { class: `badge sev-${s}`, text: `${n.toLocaleString()} ${s}` })));
  }

  function projectCard(index) {
    const project = projects[index];
    const findings = projectFindings[index];
    const production = findings.filter((f) => f.role !== "test").length;
    const most = Math.max(1, ...projectFindings.map((fs) => fs.length));
    const top = algorithmCounts(findings).slice(0, 4).map(([name, e]) => `${name} ${e.total}`).join(" · ");
    const card = el("button", { type: "button", class: "card" }, [
      el("span", { class: "card-name", text: project.name }),
      project.root ? el("span", { class: "card-root", text: project.root }) : null,
      findings.length === 0
        ? el("span", { class: "card-clean", text: `✓ Clean · ${plural(project.files_scanned, "file", "files")} scanned` })
        : [
          el("p", { class: "card-figure" }, [findings.length.toLocaleString(),
            el("span", { text: `${findings.length === 1 ? "finding" : "findings"} · ${production.toLocaleString()} in production` })]),
          el("span", { class: "card-bar", "aria-hidden": "true" },
            el("span", { style: `width:${(findings.length / most) * 100}%` })),
          severityBadges(findings),
          el("span", { class: "card-algorithms", text: top }),
        ],
      el("span", { class: "card-open", text: "Open →" }),
    ]);
    card.addEventListener("click", () => select(index));
    return withTip(card, `${project.name}: ${plural(findings.length, "finding", "findings")} in ${plural(project.files_scanned, "file", "files")} scanned`);
  }

  if (multi) {
    tabs.hidden = false;
    tabs.append(tab("All projects", allFindings.length, null), ...projectOrder.map((i) => tab(projects[i].name, projectFindings[i].length, i)));
    document.getElementById("project-cards").append(...projectOrder.map(projectCard));
    const affected = projectFindings.filter((fs) => fs.length).length;
    document.getElementById("projects-count").textContent =
      `${affected.toLocaleString()} of ${plural(projects.length, "project", "projects")} with findings`;
  }

  // ---- Overview of the scope -------------------------------------------------
  function renderOverview(findings, filesScanned) {
    const summary = summarize(findings, filesScanned);
    const name = scope !== null ? projects[scope].name : (projects.length === 1 ? projects[0].name : null);
    document.getElementById("title").textContent = name
      ? `${name}: quantum-vulnerable cryptography`
      : "Quantum-vulnerable cryptography report";
    const where = scope === null && multi ? ` across ${plural(projects.length, "project", "projects")}` : "";
    document.getElementById("lede").textContent = summary.findings === 0
      ? `No quantum-vulnerable cryptography found in ${plural(summary.files_scanned, "file", "files")}${where}.`
      : `${plural(summary.findings, "finding", "findings")} in ${plural(summary.files_with_findings, "file", "files")}, out of ${plural(summary.files_scanned, "file", "files")} scanned${where}.`;

    const production = summary.findings - summary.in_tests;
    const shor = findings.filter((f) => f.category === "shor").length;
    const kpis = [
      ["Findings", summary.findings, `${plural(summary.files_with_findings, "file", "files")}`],
      ["In production code", production, `${summary.in_tests.toLocaleString()} more in tests`],
      ["Broken by Shor", shor, "need post-quantum algorithms"],
      ["In transition", summary.in_transition, "next to post-quantum code"],
      ["Auto-fixable", summary.fixable, "mechanical fix available"],
    ];
    document.getElementById("kpis").replaceChildren(...kpis.map(([label, value, hint]) =>
      el("div", { class: "kpi" }, [
        el("p", { class: "kpi-label", text: label }),
        el("p", { class: "kpi-value", text: value.toLocaleString() }),
        el("p", { class: "kpi-hint", text: hint }),
      ])));

    const ready = summary.findings ? Math.round((summary.in_transition / summary.findings) * 100) : 100;
    document.getElementById("readiness").replaceChildren(
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

    const severityCounts = SEVERITIES.map((s) => [s, summary.by_severity[s] || 0]).filter(([, n]) => n > 0);
    const maxSeverity = Math.max(1, ...severityCounts.map(([, n]) => n));
    const severityBox = document.getElementById("severities");
    severityBox.replaceChildren();
    if (severityCounts.length === 0) severityBox.append(el("p", { class: "panel-note", text: "Nothing to report." }));
    for (const [severity, n] of severityCounts) {
      severityBox.append(withTip(el("div", { class: "sev-row" }, [
        el("span", {}, el("span", { class: `badge sev-${severity}`, text: severity })),
        el("div", { class: "sev-track" }, el("div", { class: `sev-fill fill-${severity}`, style: `width:${(n / maxSeverity) * 100}%` })),
        el("span", { class: "sev-count", text: n.toLocaleString() }),
      ]), `${severity}: ${plural(n, "finding", "findings")}`));
    }

    // By algorithm: one hue, magnitude, sorted.
    const algorithms = algorithmCounts(findings);
    const maxAlgorithm = Math.max(1, ...algorithms.map(([, e]) => e.total));
    const bars = document.getElementById("algorithms");
    const tableBody = document.querySelector("#algorithm-table tbody");
    bars.replaceChildren();
    tableBody.replaceChildren();
    if (algorithms.length === 0) bars.append(el("p", { class: "panel-note", text: "Nothing to report." }));
    for (const [name, entry] of algorithms) {
      const bar = el("button", { type: "button", class: "bar", "aria-pressed": "false", "data-algorithm": name }, [
        el("span", { class: "bar-label", text: name }),
        el("span", { class: "bar-track" }, el("span", { class: "bar-fill", style: `width:${(entry.total / maxAlgorithm) * 100}%` })),
        el("span", { class: "bar-value", text: entry.total.toLocaleString() }),
      ]);
      bar.addEventListener("click", () => {
        filters.algorithm = filters.algorithm === name ? "" : name;
        controls.algorithm.value = filters.algorithm;
        renderFindings();
      });
      bars.append(withTip(bar, `${name}: ${plural(entry.total, "finding", "findings")} (${(entry.total - entry.test).toLocaleString()} production, ${entry.test.toLocaleString()} test)`));
      tableBody.append(el("tr", {}, [
        el("th", { scope: "row", text: name }),
        el("td", { text: entry.total.toLocaleString() }),
        el("td", { text: (entry.total - entry.test).toLocaleString() }),
        el("td", { text: entry.test.toLocaleString() }),
      ]));
    }

    // Filter options follow the scope.
    controls.severity.replaceChildren(el("option", { value: "", text: "All" }),
      ...severityCounts.map(([s]) => el("option", { value: s, text: s })));
    controls.algorithm.replaceChildren(el("option", { value: "", text: "All" }),
      ...algorithms.map(([name]) => el("option", { value: name, text: name })));
  }

  // ---- Filters -------------------------------------------------------------
  const controls = {
    q: document.getElementById("filter-q"),
    severity: document.getElementById("filter-severity"),
    status: document.getElementById("filter-status"),
    role: document.getElementById("filter-role"),
    algorithm: document.getElementById("filter-algorithm"),
  };
  for (const [key, control] of Object.entries(controls)) {
    control.addEventListener("input", () => { filters[key] = control.value.trim(); renderFindings(); });
  }
  function resetFilters() {
    for (const [key, control] of Object.entries(controls)) { control.value = ""; filters[key] = ""; }
  }
  document.getElementById("filter-reset").addEventListener("click", () => { resetFilters(); renderFindings(); });

  function matches(f) {
    if (filters.severity && f.severity !== filters.severity) return false;
    if (filters.status && f.status !== filters.status) return false;
    if (filters.role && f.role !== filters.role) return false;
    if (filters.algorithm && f.algorithm !== filters.algorithm) return false;
    if (filters.q) {
      const haystack = `${f.path} ${f.algorithm} ${f.rule_id} ${f.title} ${f.detail || ""}`.toLowerCase();
      if (!haystack.includes(filters.q.toLowerCase())) return false;
    }
    return true;
  }

  // ---- Findings ------------------------------------------------------------
  function codeBlock(f) {
    if (f.snippet.lines.length === 0) return null;
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
        f.snippet.lines.length ? el("span", { class: "where", text: `line ${start.line}, column ${start.column}` }) : null,
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
  /** Paths are shown relative to their project when one is open. */
  const shownPath = (path) => {
    const open = scope !== null ? projects[scope] : (projects.length === 1 ? projects[0] : null);
    const root = open ? open.root : "";
    return root && path.startsWith(`${root}/`) ? path.slice(root.length + 1) : path;
  };

  function renderFindings() {
    for (const bar of document.querySelectorAll("#algorithms .bar")) {
      bar.setAttribute("aria-pressed", String(bar.dataset.algorithm === filters.algorithm));
    }
    const findings = allFindings.filter((f) => inScope(f, scope));
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
    // Production before tests, then the most severe files, then by path.
    const byFile = new Map();
    for (const f of shown) {
      if (!byFile.has(f.path)) byFile.set(f.path, []);
      byFile.get(f.path).push(f);
    }
    const files = [...byFile.entries()].sort((a, b) => {
      const tests = (fs) => (fs.every((f) => f.role === "test") ? 1 : 0);
      const worst = (fs) => Math.min(...fs.map((f) => SEVERITY_RANK[f.severity] ?? 9));
      return tests(a[1]) - tests(b[1]) || worst(a[1]) - worst(b[1]) || a[0].localeCompare(b[0]);
    });
    const openAll = files.length <= 12;
    for (const [path, fileFindings] of files) {
      const tests = fileFindings.every((f) => f.role === "test");
      const project = scope === null && multi && fileFindings[0].project !== null && fileFindings[0].project !== undefined
        ? projects[fileFindings[0].project] : null;
      list.append(el("details", { class: "file", open: openAll }, [
        el("summary", {}, [
          el("span", { class: "file-path", title: path, text: shownPath(path) }),
          project ? el("span", { class: "pill", text: project.name }) : null,
          tests ? el("span", { class: "pill pill-test", text: "test code" }) : null,
          el("span", { class: "file-count", text: plural(fileFindings.length, "finding", "findings") }),
        ]),
        ...fileFindings.map(findingCard),
      ]));
    }
  }

  // ---- Scope: one project or all, kept in the URL -------------------------------
  function select(index, push = true) {
    scope = index;
    for (const button of tabs.querySelectorAll(".tab")) {
      const selected = button.dataset.scope === (index === null ? "all" : String(index));
      button.setAttribute("aria-selected", String(selected));
      if (selected) button.scrollIntoView({ block: "nearest", inline: "nearest" });
    }
    document.getElementById("projects-section").hidden = !(multi && index === null);
    const files = index === null ? data.summary.files_scanned : projects[index].files_scanned;
    resetFilters();
    renderOverview(allFindings.filter((f) => inScope(f, index)), files);
    renderFindings();
    if (push && multi) {
      const hash = index === null ? "" : `#project=${encodeURIComponent(projects[index].name)}`;
      history.replaceState(null, "", hash || window.location.pathname + window.location.search);
      window.scrollTo({ top: 0 });
    }
  }

  function fromHash() {
    const match = /^#project=(.+)$/.exec(window.location.hash);
    if (!match || !multi) return null;
    const name = decodeURIComponent(match[1]);
    const index = projects.findIndex((p) => p.name === name);
    return index < 0 ? null : index;
  }

  window.addEventListener("hashchange", () => select(fromHash(), false));
  select(fromHash(), false);
})();
