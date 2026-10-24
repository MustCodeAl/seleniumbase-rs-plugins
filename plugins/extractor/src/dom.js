function (req) {
  "use strict";
  // Reads the page the plugin is in. Pure: no network, no writes, page text is
  // data and is never evaluated. It walks at most limits.max_nodes nodes and
  // says so (truncated) when it stopped early.
  //
  // req.mode "discover": finds structure; the answer is { candidates, truncated, nodes }.
  // req.mode "extract":  reads req.schema (may be null) and the page parts in
  //                      req.page; the answer is { records, errors, page, truncated, nodes }.
  const limits = req.limits;
  const SAMPLE = 5;
  const SKIP = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEMPLATE", "SVG", "HEAD"]);
  const PRICE_KEYS = new Set(["price", "lowPrice", "highPrice"]);
  let nodes = 0;
  let truncated = false;
  const errors = [];

  function spend(count) {
    nodes += count === undefined ? 1 : count;
    if (nodes > limits.max_nodes) {
      truncated = true;
      return false;
    }
    return true;
  }
  const clean = (s) => String(s === null || s === undefined ? "" : s).replace(/\s+/g, " ").trim();
  const clip = (s, n) => (s.length > n ? s.slice(0, n) : s);
  const esc = (s) =>
    typeof CSS !== "undefined" && CSS.escape ? CSS.escape(s) : String(s).replace(/[^\w-]/g, "\\$&");
  const slug = (s) =>
    clean(s).toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 48);

  function uniqueName(base, taken) {
    let name = base || "field";
    let n = 2;
    while (taken.has(name)) {
      name = (base || "field") + "_" + n++;
    }
    taken.add(name);
    return name;
  }

  // ---- reading values --------------------------------------------------------

  function read(el, field) {
    if (!el) {
      return null;
    }
    if (field.attr) {
      // The element's property is the absolute address, as the browser resolves it.
      if ((field.attr === "href" || field.attr === "src") && typeof el[field.attr] === "string") {
        return el[field.attr];
      }
      const value = el.getAttribute(field.attr);
      return value === null ? null : clean(value);
    }
    return clean(el.textContent);
  }

  function attempt(field, action) {
    try {
      return action();
    } catch (error) {
      errors.push("field " + field.name + ": " + clean(error && error.message ? error.message : error));
      return null;
    }
  }

  // ---- JSON-LD ---------------------------------------------------------------

  function collect(node, found, depth) {
    if (depth > 6) {
      return;
    }
    if (Array.isArray(node)) {
      node.forEach((child) => collect(child, found, depth + 1));
    } else if (node && typeof node === "object") {
      if (node["@graph"]) {
        collect(node["@graph"], found, depth + 1);
      }
      if (node["@type"]) {
        found.push(node);
      }
    }
  }

  function jsonLdNodes() {
    const found = [];
    for (const el of document.querySelectorAll('script[type="application/ld+json"]')) {
      if (!spend()) {
        break;
      }
      try {
        collect(JSON.parse(el.textContent), found, 0);
      } catch (error) {
        // Not JSON: ignore this block.
      }
    }
    return found;
  }

  const typeOf = (node) => String(Array.isArray(node["@type"]) ? node["@type"][0] : node["@type"]);

  // Every value at a dotted path, each with the object it sits in.
  function valuesAt(node, path) {
    let current = [{ value: node, parent: null }];
    for (const key of path.split(".")) {
      const next = [];
      for (const { value } of current) {
        if (value && typeof value === "object" && !Array.isArray(value)) {
          const child = value[key];
          for (const item of Array.isArray(child) ? child : child === undefined ? [] : [child]) {
            next.push({ value: item, parent: value });
          }
        }
      }
      current = next;
    }
    const last = path.split(".").pop();
    const out = [];
    for (const { value, parent } of current) {
      if (value === null || typeof value === "object") {
        continue;
      }
      let text = String(value);
      // A price is only a number until it meets its currency.
      if (PRICE_KEYS.has(last) && parent && typeof parent.priceCurrency === "string") {
        text += " " + parent.priceCurrency;
      }
      out.push(text);
    }
    return out;
  }

  function leafPaths(node, prefix, depth, out) {
    if (depth > 3 || !node || typeof node !== "object") {
      return;
    }
    for (const key of Object.keys(node)) {
      if (key.charAt(0) === "@" || (prefix === "" && key === "priceCurrency")) {
        continue;
      }
      let value = node[key];
      if (Array.isArray(value)) {
        value = value[0];
      }
      const path = prefix ? prefix + "." + key : key;
      if (value !== null && typeof value === "object") {
        leafPaths(value, path, depth + 1, out);
      } else if (value !== undefined && key !== "priceCurrency") {
        out.push(path);
      }
    }
  }

  function discoverJsonLd() {
    const groups = new Map();
    for (const node of jsonLdNodes()) {
      const type = typeOf(node);
      if (!groups.has(type)) {
        groups.set(type, []);
      }
      groups.get(type).push(node);
    }
    const candidates = [];
    for (const [type, members] of groups) {
      const fields = new Map();
      for (const node of members) {
        const paths = [];
        leafPaths(node, "", 0, paths);
        for (const path of new Set(paths)) {
          const field = fields.get(path) || { path, present: 0, samples: [] };
          const values = valuesAt(node, path);
          if (values.length > 0 && values[0] !== "") {
            field.present += 1;
            if (field.samples.length < SAMPLE) {
              field.samples.push(clip(values[0], 300));
            }
          }
          fields.set(path, field);
        }
      }
      const taken = new Set();
      const listed = [];
      for (const field of fields.values()) {
        if (field.present === 0 || listed.length >= limits.max_fields) {
          continue;
        }
        listed.push({
          name: uniqueName(slug(field.path.split(".").pop()), taken),
          path: field.path,
          samples: field.samples,
          present: field.present,
          total: members.length,
        });
      }
      if (listed.length > 0) {
        candidates.push({ source: "json-ld", item: type, skip: 0, items: members.length, fields: listed });
      }
    }
    return candidates;
  }

  // ---- selectors -------------------------------------------------------------

  function segment(el, useId) {
    if (useId && el.id && /^[A-Za-z][\w-]*$/.test(el.id)) {
      return "#" + esc(el.id);
    }
    let selector = el.tagName.toLowerCase();
    for (const name of Array.from(el.classList).slice(0, 3)) {
      selector += "." + esc(name);
    }
    return selector;
  }

  // A selector for el that matches `expected` elements: its own tag and
  // classes, then its ancestors until the count is right.
  function uniqueSelector(el, expected, useId) {
    let selector = segment(el, useId);
    let current = el;
    for (let depth = 0; depth < 6; depth++) {
      let count;
      try {
        count = document.querySelectorAll(selector).length;
      } catch (error) {
        return null;
      }
      if (count === expected) {
        return selector;
      }
      current = current.parentElement;
      if (!current || current === document.body || current === document.documentElement) {
        break;
      }
      selector = segment(current, true) + " > " + selector;
    }
    return selector;
  }

  // The path from root down to el, with :nth-of-type where siblings look alike.
  function relativePath(el, root, strict) {
    const parts = [];
    for (let node = el; node && node !== root; node = node.parentElement) {
      let part = segment(node, false);
      const parent = node.parentElement;
      if (parent) {
        const twins = Array.from(parent.children).filter(
          (other) => other.tagName === node.tagName && (strict || other.className === node.className)
        );
        if (twins.length > 1) {
          part += ":nth-of-type(" + (Array.from(parent.children).filter((o) => o.tagName === node.tagName).indexOf(node) + 1) + ")";
        }
      }
      parts.unshift(part);
    }
    return parts.join(" > ");
  }

  function fieldName(el, taken) {
    let raw = el.getAttribute("itemprop") || el.getAttribute("data-field") || el.getAttribute("aria-label") || "";
    if (!raw) {
      raw = Array.from(el.classList).find((name) => /[a-z]/i.test(name)) || el.tagName.toLowerCase();
    }
    return uniqueName(slug(raw), taken);
  }

  // ---- tables ----------------------------------------------------------------

  function discoverTables() {
    const candidates = [];
    for (const table of document.querySelectorAll("table")) {
      if (!spend()) {
        break;
      }
      const rows = Array.from(table.rows);
      if (rows.length < 2 || rows[0].cells.length < 2) {
        continue;
      }
      const body = rows.slice(1, 1 + 200);
      if (!spend(body.length)) {
        break;
      }
      const taken = new Set();
      const fields = [];
      Array.from(rows[0].cells).slice(0, limits.max_fields).forEach((cell, index) => {
        const samples = [];
        let present = 0;
        for (const row of body) {
          const text = row.cells[index] ? clean(row.cells[index].textContent) : "";
          if (text !== "") {
            present += 1;
            if (samples.length < SAMPLE) {
              samples.push(clip(text, 300));
            }
          }
        }
        const nth = index + 1;
        fields.push({
          name: uniqueName(slug(cell.textContent) || "column_" + nth, taken),
          selector: "td:nth-child(" + nth + "), th:nth-child(" + nth + ")",
          samples,
          present,
          total: body.length,
        });
      });
      const selector = uniqueSelector(table, 1, true);
      if (selector && fields.some((field) => field.present > 0)) {
        candidates.push({ source: "table", item: selector + " tr", skip: 1, items: body.length, fields });
      }
    }
    return candidates;
  }

  // ---- repeated structure ----------------------------------------------------

  const NOT_REPEATS = new Set(["TR", "TD", "TH", "THEAD", "TBODY", "TFOOT", "OPTION", "BR", "HR", "SOURCE", "COL"]);

  function itemFields(items) {
    const taken = new Set();
    const found = new Map();
    const sample = items.slice(0, 12);
    for (const item of sample) {
      if (!spend(item.querySelectorAll("*").length + 1)) {
        break;
      }
      const seen = new Set();
      const add = (el, attr, path) => {
        const key = path + "|" + (attr || "");
        if (seen.has(key)) {
          return;
        }
        seen.add(key);
        let field = found.get(key);
        if (!field) {
          field = { selector: path, attr, el, present: 0, samples: [] };
          found.set(key, field);
        }
        const value = read(el, { attr });
        if (value) {
          field.present += 1;
          if (field.samples.length < SAMPLE) {
            field.samples.push(clip(value, 300));
          }
        }
      };
      for (const el of item.querySelectorAll("*")) {
        if (SKIP.has(el.tagName.toUpperCase()) || el.closest("svg")) {
          continue;
        }
        const tag = el.tagName.toUpperCase();
        if (tag === "A" && el.getAttribute("href")) {
          add(el, "href", relativePath(el, item, false));
        }
        if (tag === "IMG" && el.getAttribute("src")) {
          add(el, "src", relativePath(el, item, false));
        }
        if (el.children.length === 0 && clean(el.textContent) !== "") {
          add(el, null, relativePath(el, item, false));
        }
      }
    }
    const fields = [];
    for (const field of found.values()) {
      if (field.present * 2 < sample.length || fields.length >= limits.max_fields) {
        continue;
      }
      let name = fieldName(field.el, taken);
      if (field.attr === "href" && !/url|link|href/.test(name)) {
        name = uniqueName(name + "_url", taken);
      }
      fields.push({
        name,
        selector: field.selector,
        attr: field.attr || undefined,
        samples: field.samples,
        present: field.present,
        total: sample.length,
      });
    }
    return fields;
  }

  function discoverRepeats() {
    const candidates = [];
    const stack = document.body ? [document.body] : [];
    while (stack.length > 0) {
      const parent = stack.pop();
      if (!spend()) {
        break;
      }
      const groups = new Map();
      for (const child of parent.children) {
        if (SKIP.has(child.tagName.toUpperCase())) {
          continue;
        }
        stack.push(child);
        if (NOT_REPEATS.has(child.tagName.toUpperCase())) {
          continue;
        }
        const signature = child.tagName + "." + Array.from(child.classList).sort().join(".");
        if (!groups.has(signature)) {
          groups.set(signature, []);
        }
        groups.get(signature).push(child);
      }
      for (const items of groups.values()) {
        if (items.length < limits.min_repeats || clean(items[0].textContent).length < 8) {
          continue;
        }
        const fields = itemFields(items);
        if (fields.length < 2) {
          continue;
        }
        const selector = uniqueSelector(items[0], items.length, false);
        if (selector) {
          candidates.push({ source: "repeat", item: selector, skip: 0, items: items.length, fields });
        }
      }
    }
    candidates.sort((a, b) => b.items * b.fields.length - a.items * a.fields.length);
    return candidates.slice(0, 3);
  }

  // ---- extraction ------------------------------------------------------------

  function extractDom(schema) {
    const skip = schema.skip || 0;
    let roots = [document];
    if (schema.item) {
      try {
        roots = Array.from(document.querySelectorAll(schema.item)).slice(skip);
      } catch (error) {
        errors.push("item: " + clean(error.message));
        return [];
      }
    }
    const records = [];
    for (const root of roots) {
      if (records.length >= limits.max_records) {
        truncated = true;
        break;
      }
      if (!spend(schema.fields.length)) {
        break;
      }
      const record = {};
      for (const field of schema.fields) {
        record[field.name] = attempt(field, () =>
          field.all
            ? Array.from(root.querySelectorAll(field.selector))
                .slice(0, 100)
                .map((el) => read(el, field))
                .filter((value) => value !== null && value !== "")
            : read(root.querySelector(field.selector), field)
        );
      }
      records.push(record);
    }
    return records;
  }

  function extractJsonLd(schema) {
    const wanted = jsonLdNodes().filter((node) => !schema.item || typeOf(node) === schema.item);
    return wanted.slice(0, limits.max_records).map((node) => {
      const record = {};
      for (const field of schema.fields) {
        const values = valuesAt(node, field.path);
        record[field.name] = field.all ? values : values.length > 0 ? values[0] : null;
      }
      return record;
    });
  }

  // ---- the page itself -------------------------------------------------------

  function pageParts(want) {
    const page = { title: document.title, url: location.href };
    if (want.text && document.body) {
      page.text = clip(
        (document.body.innerText || document.body.textContent || "").replace(/[ \t]+/g, " ").replace(/\n{3,}/g, "\n\n").trim(),
        limits.max_text
      );
    }
    if (want.links) {
      const seen = new Set();
      page.links = [];
      for (const a of document.querySelectorAll("a[href]")) {
        if (page.links.length >= limits.max_links || !spend()) {
          truncated = true;
          break;
        }
        const href = typeof a.href === "string" ? a.href : "";
        if (/^https?:/i.test(href) && !seen.has(href)) {
          seen.add(href);
          page.links.push({ href, text: clip(clean(a.textContent), 200) });
        }
      }
    }
    if (want.tables) {
      page.tables = [];
      for (const table of Array.from(document.querySelectorAll("table")).slice(0, 20)) {
        const rows = Array.from(table.rows).slice(0, 201);
        if (rows.length === 0 || !spend(rows.length)) {
          continue;
        }
        const cells = (row) => Array.from(row.cells).slice(0, 30).map((cell) => clip(clean(cell.textContent), 300));
        page.tables.push({ headers: cells(rows[0]), rows: rows.slice(1).map(cells) });
      }
    }
    if (want.meta) {
      page.meta = {};
      for (const meta of Array.from(document.querySelectorAll("meta[content]")).slice(0, 80)) {
        const key = meta.getAttribute("property") || meta.getAttribute("name");
        if (key && /^(description|keywords|author|og:.+|twitter:.+|article:.+)$/i.test(key)) {
          page.meta[key.toLowerCase()] = clip(clean(meta.getAttribute("content")), 500);
        }
      }
      const canonical = document.querySelector('link[rel="canonical"][href]');
      if (canonical && typeof canonical.href === "string") {
        page.meta.canonical = canonical.href;
      }
      if (document.documentElement.lang) {
        page.meta.lang = document.documentElement.lang;
      }
    }
    return page;
  }

  // ---- the two modes ---------------------------------------------------------

  if (req.mode === "discover") {
    const candidates = discoverJsonLd().concat(discoverTables(), discoverRepeats());
    return { candidates, truncated, nodes };
  }
  if (req.mode === "extract") {
    let records = [];
    if (req.schema) {
      records = req.schema.source === "json-ld" ? extractJsonLd(req.schema) : extractDom(req.schema);
    }
    const page = req.page ? pageParts(req.page) : null;
    return { records, errors, page, truncated, nodes };
  }
  throw new Error("unknown mode " + req.mode);
}
