"use strict";
(function () {
  const data = JSON.parse(document.getElementById("shorwatch-data").textContent);
  const findings = data.findings;
  const projects = data.projects || [];
  const multi = projects.length > 1;
  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const MARK = { critical: "◆", high: "▲", medium: "●", low: "○", info: "○" };
  const RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));
  const PAGE = 25;
  const URGENT = 3;
  findings.forEach((f, i) => { f.id = i; });

  // Every piece of scanned text goes through textContent: never markup.
  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs || {})) {
      if (value === undefined || value === null || value === false) continue;
      if (key === "text") node.textContent = value;
      else if (key === "class") node.className = value;
      else if (key === "value") node.value = value;
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      // Links come from rules too (`--rules` may be someone else's): only
      // the report's own routes, the web and the editor, never `javascript:`.
      else if (key === "href" && !/^(#|https?:\/\/|vscode:\/\/)/i.test(String(value))) continue;
      else node.setAttribute(key, value === true ? "" : value);
    }
    for (const child of [].concat(children ?? []).flat(Infinity)) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  const num = (n) => n.toLocaleString("en-US");
  const plural = (n, one, many) => `${num(n)} ${n === 1 ? one : many}`;
  const fileName = (path) => path.split("/").pop();
  const isTest = (f) => f.role === "test";
  const capitalize = (s) => s.charAt(0).toUpperCase() + s.slice(1);
  const projectOf = (f) => (f.project === null || f.project === undefined ? null : projects[f.project]);
  /** A path as people read it: relative to its project. */
  function shownPath(path) {
    const owner = findings.find((f) => f.path === path);
    const project = owner ? projectOf(owner) : projects[0];
    const root = project ? project.root : "";
    return root && path.startsWith(`${root}/`) ? path.slice(root.length + 1) : path;
  }
  /** Text that may break after each `/`, never inside a name. */
  function breakable(path) {
    return path.split("/").flatMap((part, i, all) => (i < all.length - 1 ? [`${part}/`, el("wbr")] : [part]));
  }

  // ---- Theme ---------------------------------------------------------------
  const THEMES = ["auto", "light", "dark"];
  const toggle = document.getElementById("theme-toggle");
  let theme = "auto";
  try { theme = localStorage.getItem("shorwatch-theme") || "auto"; } catch (_) { /* storage blocked */ }
  if (!THEMES.includes(theme)) theme = "auto";
  function applyTheme() {
    if (theme === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
    toggle.textContent = `Theme: ${theme}`;
  }
  applyTheme();
  toggle.addEventListener("click", () => {
    theme = THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length];
    applyTheme();
    try { localStorage.setItem("shorwatch-theme", theme); } catch (_) { /* storage blocked */ }
  });

  // ---- Routes: the cover, or a chapter of findings ----------------------------
  // `#/findings?sev=high&project=keycloak&alg=RSA&cat=shor&f=12` opens a
  // chapter; anything else is the cover (`#where` scrolls to its section).
  const FILTERS = ["sev", "project", "alg", "cat"];
  function chapterHref(params) {
    const query = new URLSearchParams();
    for (const key of [...FILTERS, "f"]) {
      if (params[key] !== undefined && params[key] !== null && params[key] !== "") query.set(key, params[key]);
    }
    const text = query.toString();
    return `#/findings${text ? `?${text}` : ""}`;
  }
  function route() {
    const hash = window.location.hash;
    if (!hash.startsWith("#/findings")) return { cover: true, anchor: decodeURIComponent(hash.slice(1)), params: {} };
    const query = new URLSearchParams(hash.split("?")[1] || "");
    const params = {};
    for (const key of [...FILTERS, "f"]) if (query.has(key)) params[key] = query.get(key);
    return { cover: false, params };
  }

  function matches(f, params) {
    if (params.sev && f.severity !== params.sev) return false;
    if (params.alg && f.algorithm !== params.alg) return false;
    if (params.cat && f.category !== params.cat) return false;
    if (params.project) {
      const project = projectOf(f);
      if (!project || project.name !== params.project) return false;
    }
    return true;
  }

  /** `RSA ×3, SHA-1`, most frequent first. */
  function algorithmList(fs, limit) {
    const counts = new Map();
    for (const f of fs) counts.set(f.algorithm, (counts.get(f.algorithm) || 0) + 1);
    const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const shown = sorted.slice(0, limit || sorted.length).map(([a, n]) => (n > 1 ? `${a} ×${n}` : a));
    if (limit && sorted.length > limit) shown.push("…");
    return shown.join(", ");
  }

  function bySeverity(fs) {
    const counts = {};
    for (const f of fs) counts[f.severity] = (counts[f.severity] || 0) + 1;
    return SEVERITIES.filter((s) => counts[s]).map((s) => [s, counts[s]]);
  }

  function groupByFile(fs) {
    const map = new Map();
    for (const f of fs) {
      if (!map.has(f.path)) map.set(f.path, []);
      map.get(f.path).push(f);
    }
    return [...map.entries()].map(([path, list]) => ({
      path,
      fs: list.sort((a, b) => a.location.start.line - b.location.start.line || a.algorithm.localeCompare(b.algorithm)),
      test: list.every(isTest),
    }));
  }

  // ---- Shared pieces ------------------------------------------------------------
  function codeBlock(f) {
    if (!f.snippet || f.snippet.lines.length === 0) return null;
    const start = f.location.start;
    const end = f.location.end;
    return el("pre", { class: "code", "aria-label": `Source around line ${start.line}` },
      f.snippet.lines.map((text, i) => {
        const number = f.snippet.first_line + i;
        const hit = number >= start.line && number <= end.line;
        if (!hit) return el("span", { class: "code-line" }, [el("span", { class: "ln", text: number }), el("span", { text })]);
        // Columns are Unicode code points, 1-based.
        const chars = Array.from(text);
        const from = number === start.line ? start.column - 1 : 0;
        const to = number === end.line ? end.column - 1 : chars.length;
        return el("span", { class: "code-line hit" }, [
          el("span", { class: "ln", text: number }),
          el("span", {}, [chars.slice(0, from).join(""), el("mark", { text: chars.slice(from, to).join("") }), chars.slice(to).join("")]),
        ]);
      }));
  }

  function flowSteps(f) {
    if (!f.flow || f.flow.length === 0) return null;
    // Steps on the same line ("written here", "passed as x") read as one.
    const merged = [];
    for (const step of f.flow) {
      const path = step.path || f.path;
      const last = merged[merged.length - 1];
      if (last && last.path === path && last.line === step.location.start.line) last.notes.push(step.note);
      else merged.push({ path, line: step.location.start.line, notes: [step.note] });
    }
    merged.push({ path: f.path, line: f.location.start.line, notes: ["used here"] });
    return el("ol", { class: "flow", "aria-label": "How the value gets here" }, merged.map((s) =>
      el("li", {}, [el("strong", { text: s.notes.join(", ") }), el("span", { class: "mono", title: s.path, text: `${fileName(s.path)}:${s.line}` })])));
  }

  function badge(severity) {
    return el("span", { class: `badge sev-${severity}`, text: `${MARK[severity] || ""} ${severity}` });
  }

  function explanation(f) {
    return el("div", { class: "two-col" }, [
      el("p", {}, [el("span", { class: "label", text: "Why it matters" }), f.message]),
      el("p", {}, [el("span", { class: "label", text: "What to do" }), f.suggestion]),
    ]);
  }

  /** Production first, then the most severe, vulnerable before migrating, then
   *  different algorithms: the terminal's "most urgent". */
  function urgent() {
    const sorted = [...findings].sort((a, b) =>
      (isTest(a) - isTest(b)) || (RANK[a.severity] - RANK[b.severity])
      || ((a.status === "in_transition") - (b.status === "in_transition")) || (a.id - b.id));
    const picked = [];
    for (const f of sorted) if (picked.length < URGENT && picked.every((p) => p.algorithm !== f.algorithm)) picked.push(f);
    for (const f of sorted) if (picked.length < URGENT && !picked.includes(f)) picked.push(f);
    return picked;
  }

  // ---- Cover ----------------------------------------------------------------------
  function renderCover() {
    const summary = data.summary;
    const production = findings.filter((f) => !isTest(f)).length;
    const high = findings.filter((f) => f.severity === "high").length;
    const shor = findings.filter((f) => f.category === "shor").length;
    const ready = findings.length ? Math.round((summary.in_transition / findings.length) * 100) : 100;
    const scope = multi
      ? `${plural(projects.length, "project", "projects")} · ${plural(summary.files_scanned, "file", "files")} scanned`
      : `${projects[0] ? `${projects[0].name} · ` : ""}${plural(summary.files_scanned, "file", "files")} scanned`;
    const left = [
      summary.ignored_in_code ? `${num(summary.ignored_in_code)} ignored in the code` : null,
      summary.in_baseline ? `${num(summary.in_baseline)} known from the baseline` : null,
    ].filter(Boolean);
    const notCounted = left.length ? ` Not counted: ${left.join(", ")}.` : "";
    const migrating = summary.in_transition === 0
      ? "None is migrating yet."
      : `${num(summary.in_transition)} already ${summary.in_transition === 1 ? "sits" : "sit"} next to post-quantum code.`;

    const hero = el("section", { class: "hero" }, [
      el("p", { class: "kicker", text: scope }),
      el("h1", {
        class: "headline",
        text: findings.length === 0
          ? `No ${summary.in_baseline ? "new " : ""}quantum-vulnerable cryptography found.`
          : `${num(findings.length)} ${findings.length === 1 ? "place" : "places"} where today’s cryptography ${shor ? "falls to" : "is weakened by"} a quantum computer.`,
      }),
      el("p", {
        class: "lede",
        text: findings.length === 0
          ? `No rule matched in the scanned code, configuration or key material.${notCounted}`
          : `${shor
            ? "RSA, elliptic curves and Diffie-Hellman are broken outright by Shor’s algorithm; data protected with them today can be recorded now and opened later."
            : "Grover’s algorithm halves the strength of these algorithms; larger keys and hashes fix them."} ${num(production)} of these findings ${production === 1 ? "is" : "are"} in production code. ${migrating}${notCounted}`,
      }),
      findings.length === 0 ? null : el("div", { class: "stats" }, [
        stat(production, "in production code →", chapterHref({})),
        stat(high, "high severity →", high ? chapterHref({ sev: "high" }) : null, "sev-high"),
        stat(shor, "broken by Shor’s algorithm →", shor ? chapterHref({ cat: "shor" }) : null),
        stat(`${ready}%`, "already in transition to ML-KEM / ML-DSA", null),
      ]),
    ]);
    const sections = [hero];
    if (findings.length) sections.push(whereItLives(), fixFirst(), algorithmsSection(), severitySection());
    document.getElementById("cover").replaceChildren(...sections);
  }

  function stat(value, label, href, valueClass) {
    const children = [
      el("span", { class: `stat-value ${valueClass || ""}`, text: typeof value === "number" ? num(value) : value }),
      el("span", { class: "stat-label", text: href ? label : label.replace(" →", "") }),
    ];
    return href ? el("a", { class: "stat", href }, children) : el("div", { class: "stat" }, children);
  }

  function sectionHead(id, title, note) {
    return el("div", { class: "section-head" }, [
      el("h2", { class: "section-title", id, text: title }),
      note ? el("p", { class: "section-note", text: note }) : null,
    ]);
  }

  function severityLinks(fs, params) {
    return el("div", { class: "sev-links" }, bySeverity(fs).map(([s, n]) =>
      el("a", { class: `sev-link sev-${s}`, href: chapterHref({ ...params, sev: s }), text: `${MARK[s]} ${num(n)} ${s}` })));
  }

  function whereItLives() {
    if (multi) {
      const rows = projects.map((p, i) => ({ p, fs: findings.filter((f) => f.project === i) }))
        .sort((a, b) => b.fs.length - a.fs.length || a.p.name.localeCompare(b.p.name));
      const most = Math.max(1, ...rows.map((r) => r.fs.length));
      return el("section", {}, [
        sectionHead("where", "Where it lives", "Projects by findings. Select a project or a severity to open its chapter."),
        el("div", { class: "ruled" }, rows.map((r, i) => el("div", { class: "rank-row" }, [
          el("span", { class: "rank-n", text: String(i + 1).padStart(2, "0") }),
          el("div", {}, [
            r.fs.length
              ? el("a", { class: "rank-name", href: chapterHref({ project: r.p.name }), text: r.p.name })
              : el("span", { class: "rank-name", text: r.p.name }),
            el("span", {
              class: "rank-sub",
              text: r.fs.length
                ? `${num(r.fs.filter((f) => !isTest(f)).length)} in production code`
                : `${plural(r.p.files_scanned, "file", "files")} scanned`,
            }),
          ]),
          el("div", { class: "track", "aria-hidden": "true" }, el("div", { class: "fill", style: `width:${(r.fs.length / most) * 100}%` })),
          el("span", { class: "rank-total", text: num(r.fs.length) }),
          r.fs.length ? severityLinks(r.fs, { project: r.p.name }) : el("span", { class: "clean", text: "✓ Clean" }),
        ]))),
      ]);
    }
    // One project: the files with the most findings, production first.
    const byFile = groupByFile(findings).sort((a, b) => (a.test - b.test) || b.fs.length - a.fs.length || a.path.localeCompare(b.path));
    const shown = byFile.slice(0, 8);
    const most = Math.max(1, ...shown.map((r) => r.fs.length));
    return el("section", {}, [
      sectionHead("where", "Where it lives", `${plural(byFile.length, "file", "files")} with findings, production code first.`),
      el("div", { class: "ruled" }, shown.map((r, i) => el("div", { class: "rank-row" }, [
        el("span", { class: "rank-n", text: String(i + 1).padStart(2, "0") }),
        el("div", {}, [
          el("a", { class: "rank-name mono", href: chapterHref({ f: r.fs[0].id }), text: fileName(r.path) }),
          el("span", { class: "rank-sub" }, [breakable(shownPath(r.path).slice(0, -fileName(r.path).length)), r.test ? " · test code" : ""]),
        ]),
        el("div", { class: "track", "aria-hidden": "true" }, el("div", { class: "fill", style: `width:${(r.fs.length / most) * 100}%` })),
        el("span", { class: "rank-total", text: num(r.fs.length) }),
        el("span", { class: "file-algorithms", text: algorithmList(r.fs, 3) }),
      ]))),
      byFile.length > shown.length
        ? el("p", { class: "section-note" }, el("a", { href: chapterHref({}), text: `All ${plural(byFile.length, "file", "files")} →` }))
        : null,
    ]);
  }

  function fixFirst() {
    return el("section", {}, [
      sectionHead("first", "Fix these first", null),
      el("p", { class: "section-note", text: "Production code, highest severity, different algorithms. When the algorithm is written elsewhere, its path goes from where it is written to where it is used." }),
      urgent().map((f, i) => el("article", { class: "urgent" }, [
        el("span", { class: "urgent-n", text: String(i + 1) }),
        el("div", {}, [
          el("div", { class: "urgent-head" }, [badge(f.severity), el("h3", { class: "urgent-title", text: f.title })]),
          el("p", { class: "where" }, el("a", { href: chapterHref({ f: f.id }) }, [
            multi && projectOf(f) ? `${projectOf(f).name} · ` : "",
            breakable(`${shownPath(f.path)}:${f.location.start.line}`),
          ])),
          f.detail ? el("p", { class: "detail-line", text: f.detail }) : null,
          codeBlock(f),
          flowSteps(f),
          explanation(f),
        ]),
      ])),
    ]);
  }

  function algorithmsSection() {
    const counts = new Map();
    for (const f of findings) counts.set(f.algorithm, (counts.get(f.algorithm) || 0) + 1);
    const rows = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const most = Math.max(1, ...rows.map(([, n]) => n));
    return el("section", {}, [
      sectionHead("algorithms", "By algorithm", "Select one to open its chapter."),
      el("div", { class: "ruled algorithms" }, rows.map(([name, n]) => el("a", { class: "alg-row", href: chapterHref({ alg: name }) }, [
        el("span", { class: "alg-name", text: name }),
        el("span", { class: "track", "aria-hidden": "true" }, el("span", { class: "fill", style: `display:block;width:${(n / most) * 100}%` })),
        el("span", { class: "alg-count", text: num(n) }),
      ]))),
    ]);
  }

  function severitySection() {
    return el("section", {}, [
      sectionHead("severity", "By severity", null),
      el("div", { class: "ruled" }, bySeverity(findings).map(([s, n]) => {
        const fs = findings.filter((f) => f.severity === s);
        return el("a", { class: "sev-row", href: chapterHref({ sev: s }) }, [
          el("span", { class: "sev-row-title" }, [
            el("span", { class: `sev-${s}`, text: MARK[s] }), ` ${capitalize(s)} severity`,
            el("span", { class: "sev-row-count", text: num(n) }),
          ]),
          el("span", { class: "sev-row-more", text: `${algorithmList(fs, 3)} · open the chapter →` }),
        ]);
      })),
    ]);
  }

  // ---- Chapter ------------------------------------------------------------------
  /** What a chapter shows beyond its route, kept while the route stays. */
  const view = { key: "", query: "", files: PAGE, testsOpen: false, testFiles: PAGE, openFile: null, openFinding: null };

  function chapterTitle(params) {
    const parts = [];
    if (params.sev) parts.push(`${capitalize(params.sev)} severity`);
    if (params.cat === "shor") parts.push("Broken by Shor’s algorithm");
    else if (params.cat) parts.push(`${capitalize(params.cat)} findings`);
    if (params.alg) parts.push(params.alg);
    return parts.length ? parts.join(": ") : "All findings";
  }

  function contents(params) {
    const scoped = findings.filter((f) => matches(f, { project: params.project }));
    const link = (href, name, n, current) => el("a", { href, "aria-current": current ? "page" : null }, [
      el("span", { class: "name", text: name }), n === null ? null : el("span", { class: "n", text: num(n) })]);
    return [
      el("h2", { text: "Contents" }),
      link("#", "Cover", null, false),
      link("#where", "Where it lives", null, false),
      link("#first", "Fix these first", null, false),
      link("#algorithms", "By algorithm", null, false),
      el("h2", { text: params.project ? `Severity in ${params.project}` : "Severity" }),
      link(chapterHref({ project: params.project }), "All findings", scoped.length, !params.sev && !params.alg && !params.cat),
      bySeverity(scoped).map(([s, n]) => link(chapterHref({ project: params.project, sev: s }), `${MARK[s]} ${capitalize(s)}`, n,
        params.sev === s && !params.alg && !params.cat)),
      multi ? [
        el("h2", { text: "Projects" }),
        projects.map((p, i) => ({ p, n: findings.filter((f) => f.project === i).length }))
          .filter((r) => r.n > 0)
          .sort((a, b) => b.n - a.n)
          .map((r) => link(chapterHref({ project: r.p.name }), r.p.name, r.n, params.project === r.p.name)),
      ] : null,
    ];
  }

  function copy(button, text) {
    const done = () => {
      const old = button.textContent;
      button.textContent = "Copied";
      setTimeout(() => { button.textContent = old; }, 1400);
    };
    try {
      navigator.clipboard.writeText(text).then(done, () => window.prompt("Copy:", text));
    } catch (_) {
      window.prompt("Copy:", text);
    }
  }

  // Where the finding's lines open: VS Code for files on this machine, the
  // repository host (and its editor in the browser) for scans run in CI.
  function openLinks(f) {
    const links = data.links || {};
    const start = f.location.start;
    const end = Math.max(f.location.end.line, start.line);
    const absolute = /^(\/|[A-Za-z]:)/.test(f.path);
    const out = [];
    if (links.local_root) {
      const file = absolute ? f.path : `${links.local_root}/${f.path}`;
      out.push(el("a", { href: `vscode://file/${encodeURI(file)}:${start.line}:${start.column}`, text: "Open in VS Code" }));
    }
    if (links.web && !absolute && !f.path.split("/").includes("..")) {
      const fill = (template) => template
        .replace("{path}", f.path.split("/").map(encodeURIComponent).join("/"))
        .replace("{line}", String(start.line))
        .replace("{end}", String(end));
      out.push(el("a", { href: fill(links.web.file), rel: "noopener noreferrer", target: "_blank", text: `View on ${links.web.host}` }));
      if (links.web.editor) {
        out.push(el("a", { href: fill(links.web.editor), rel: "noopener noreferrer", target: "_blank", text: "Open in github.dev" }));
      }
    }
    return out;
  }

  function findingDetail(f, params) {
    const link = `${window.location.href.split("#")[0]}${chapterHref({ ...params, f: f.id })}`;
    return el("div", { class: "finding-detail", id: `finding-${f.id}` }, [
      el("h3", { class: "finding-title", text: f.title }),
      el("div", { class: "finding-tags" }, [
        badge(f.severity),
        el("span", {
          class: `tag ${f.status === "in_transition" ? "transition" : ""}`,
          text: f.status === "in_transition" ? "in transition" : "vulnerable",
        }),
        isTest(f) ? el("span", { class: "tag", text: "test code" }) : null,
        el("span", { class: "mono tag", text: f.rule_id }),
      ]),
      f.detail ? el("p", { class: "detail-line", text: f.detail }) : null,
      codeBlock(f),
      flowSteps(f),
      explanation(f),
      el("div", { class: "notes" }, [
        f.hybrid_evidence ? el("p", { text: `In transition: post-quantum code at line ${f.hybrid_evidence.location.start.line} (${f.hybrid_evidence.text}).` }) : null,
        f.fix ? el("p", { text: `Fix: ${f.fix.description}: replace with “${f.fix.replacement}” at line ${f.fix.location.start.line}.` }) : null,
      ]),
      el("div", { class: "actions" }, [
        openLinks(f),
        el("button", { type: "button", onclick: (e) => copy(e.currentTarget, link), text: "Copy link to this finding" }),
        el("button", { type: "button", onclick: (e) => copy(e.currentTarget, `${f.path}:${f.location.start.line}`), text: "Copy path" }),
        (f.references || []).map((r) => el("a", { href: r.url, rel: "noopener noreferrer", target: "_blank", text: r.title })),
      ]),
    ]);
  }

  function fileGroup(group, params) {
    const open = view.openFile === group.path;
    const shown = shownPath(group.path);
    const cut = shown.lastIndexOf("/");
    return el("div", { class: "file" }, [
      el("button", {
        type: "button", class: "file-row", "aria-expanded": String(open),
        onclick: () => { view.openFile = open ? null : group.path; view.openFinding = null; renderChapter(false); },
      }, [
        el("span", { class: "chevron", "aria-hidden": "true", text: open ? "▾" : "▸" }),
        el("span", { class: "file-path", title: group.path }, [el("span", { class: "dir" }, breakable(shown.slice(0, cut + 1))), shown.slice(cut + 1)]),
        el("span", { class: "file-count", text: `×${group.fs.length}` }),
        el("span", { class: "file-algorithms", text: algorithmList(group.fs, 4) }),
      ]),
      open ? el("div", { class: "file-body" }, group.fs.map((f) => {
        const expanded = view.openFinding === f.id;
        const hasCode = f.snippet && f.snippet.lines.length > 0;
        const line = hasCode ? f.snippet.lines[f.location.start.line - f.snippet.first_line] : null;
        return el("div", { class: "finding" }, [
          el("button", {
            type: "button", class: "finding-row", "aria-expanded": String(expanded),
            onclick: () => { view.openFinding = expanded ? null : f.id; renderChapter(false); },
          }, [
            el("span", { class: "finding-line", text: hasCode ? `:${f.location.start.line}` : "" }),
            el("span", { class: "finding-alg" }, [el("span", { class: `sev-${f.severity}`, text: `${MARK[f.severity]} ` }), f.algorithm]),
            el("span", { class: "finding-code", text: line ? line.trim() : (f.detail || f.title) }),
          ]),
          expanded ? findingDetail(f, params) : null,
        ]);
      })) : null,
    ]);
  }

  function renderChapter(fresh) {
    const { params } = route();
    const key = FILTERS.map((k) => params[k] || "").join("|");
    if (fresh && key !== view.key) {
      Object.assign(view, { key, query: "", files: PAGE, testsOpen: false, testFiles: PAGE, openFile: null, openFinding: null });
    }
    // A link to one finding opens its file and the finding.
    if (fresh && params.f !== undefined && findings[Number(params.f)]) {
      const f = findings[Number(params.f)];
      view.openFile = f.path;
      view.openFinding = f.id;
      view.testsOpen = view.testsOpen || isTest(f);
    }
    const scoped = findings.filter((f) => matches(f, params));
    const q = view.query.toLowerCase();
    const shown = q
      ? scoped.filter((f) => `${f.path} ${f.algorithm} ${f.rule_id} ${f.title} ${f.detail || ""}`.toLowerCase().includes(q))
      : scoped;
    const groups = groupByFile(shown).sort((a, b) => b.fs.length - a.fs.length || a.path.localeCompare(b.path));
    const production = groups.filter((g) => !g.test);
    const tests = groups.filter((g) => g.test);
    const productionCount = shown.filter((f) => !isTest(f)).length;
    const testCount = shown.length - productionCount;
    // A file opened by a link is never hidden behind "show more".
    const reveal = (list, limit) => Math.max(limit, list.findIndex((g) => g.path === view.openFile) + 1);
    const filesLimit = reveal(production, view.files);
    const testLimit = reveal(tests, view.testFiles);

    const title = chapterTitle(params);
    const fullTitle = params.project ? `${title} in ${params.project}` : title;
    document.title = `${fullTitle} · Shorwatch`;
    const chips = FILTERS.filter((k) => params[k]).map((k) => {
      const label = k === "sev"
        ? `${MARK[params.sev]} ${capitalize(params.sev)}`
        : k === "cat" ? (params.cat === "shor" ? "Shor" : capitalize(params.cat)) : params[k];
      return el("a", { class: "chip", href: chapterHref({ ...params, [k]: undefined, f: undefined }), "aria-label": `Remove filter: ${label}` },
        [label, el("span", { "aria-hidden": "true", text: "×" })]);
    });
    const search = el("input", {
      type: "search", placeholder: "Search in this chapter", value: view.query, "aria-label": "Search in this chapter",
      oninput: (e) => { view.query = e.target.value; view.files = PAGE; renderChapter(false); restoreSearch(); },
    });

    document.getElementById("contents").replaceChildren(...[contents(params)].flat(Infinity).filter(Boolean));
    document.getElementById("chapter-main").replaceChildren(...[
      el("p", { class: "crumbs" }, [
        el("a", { href: "#", text: "Report" }),
        params.project ? [" › ", el("a", { href: chapterHref({ project: params.project }), text: params.project })] : null,
        ` › ${title}`,
      ]),
      el("h1", { class: "chapter-title" }, [params.sev ? el("span", { class: `sev-${params.sev}`, text: `${MARK[params.sev]} ` }) : null, fullTitle]),
      el("p", {
        class: "chapter-lede",
        text: shown.length === 0
          ? (q ? "No finding matches this search." : "No finding here.")
          : `${plural(shown.length, "finding", "findings")}: ${num(productionCount)} in production code, across ${plural(production.length, "file", "files")}, and ${num(testCount)} in tests. Grouped by file, most findings first.`,
      }),
      el("div", { class: "filters", role: "search" }, [
        el("span", { class: "label", text: "Filters" }),
        chips.length ? chips : el("span", { class: "folded-hint", text: "None" }),
        el("label", { class: "search" }, search),
      ]),
      production.length ? [
        el("h2", { class: "group-title", text: `Production code · ${plural(productionCount, "finding", "findings")} in ${plural(production.length, "file", "files")}` }),
        el("div", { class: "files" }, production.slice(0, filesLimit).map((g) => fileGroup(g, params))),
        production.length > filesLimit ? el("button", {
          type: "button", class: "more",
          text: `Show ${Math.min(PAGE, production.length - filesLimit)} more of ${plural(production.length - filesLimit, "file", "files")}`,
          onclick: () => { view.files = filesLimit + PAGE; renderChapter(false); },
        }) : null,
      ] : null,
      tests.length ? el("div", { class: "folded" }, [
        el("button", {
          type: "button", class: "folded-head", "aria-expanded": String(view.testsOpen),
          onclick: () => { view.testsOpen = !view.testsOpen; renderChapter(false); },
        }, [
          el("span", { class: "group-title", text: `${view.testsOpen ? "▾" : "▸"} Test code · ${plural(testCount, "finding", "findings")} in ${plural(tests.length, "file", "files")}` }),
          el("span", { class: "folded-hint", text: view.testsOpen ? "Hide" : "Folded: test code does not ship. Show" }),
        ]),
        view.testsOpen ? [
          el("div", { class: "files" }, tests.slice(0, testLimit).map((g) => fileGroup(g, params))),
          tests.length > testLimit ? el("button", {
            type: "button", class: "more",
            text: `Show ${Math.min(PAGE, tests.length - testLimit)} more of ${plural(tests.length - testLimit, "test file", "test files")}`,
            onclick: () => { view.testFiles = testLimit + PAGE; renderChapter(false); },
          }) : null,
        ] : null,
      ]) : null,
      el("p", { class: "back" }, el("a", { href: "#", text: "← Back to the cover" })),
    ].flat(Infinity).filter(Boolean));

    if (fresh && view.openFinding !== null) {
      const target = document.getElementById(`finding-${view.openFinding}`);
      if (target) target.scrollIntoView({ block: "center" });
    }
  }

  function restoreSearch() {
    const input = document.querySelector(".search input");
    if (input) { input.focus(); input.setSelectionRange(input.value.length, input.value.length); }
  }

  // ---- Navigation ---------------------------------------------------------------------
  function show() {
    const current = route();
    document.getElementById("cover").hidden = !current.cover;
    document.getElementById("chapter").hidden = current.cover;
    if (current.cover) {
      document.title = "Shorwatch report";
      const target = current.anchor && document.getElementById(current.anchor);
      if (target) target.scrollIntoView();
      else window.scrollTo(0, 0);
      return;
    }
    renderChapter(true);
    if (current.params.f === undefined) window.scrollTo(0, 0);
  }

  renderCover();
  window.addEventListener("hashchange", show);
  show();
})();
