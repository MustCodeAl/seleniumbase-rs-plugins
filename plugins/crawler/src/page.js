(request) => {
  const out = {
    url: location.href,
    title: document.title || "",
    status: null,
    links: [],
    truncated: false,
    nofollow: false,
    extracted: null,
    markdown: null,
  };
  try {
    const nav = performance.getEntriesByType("navigation")[0];
    if (nav && typeof nav.responseStatus === "number" && nav.responseStatus > 0) {
      out.status = nav.responseStatus;
    }
  } catch (_) {}
  try {
    const meta = document.querySelector('meta[name="robots" i]');
    if (meta && /(^|[\s,])nofollow([\s,]|$)/i.test(meta.getAttribute("content") || "")) {
      out.nofollow = true;
    }
  } catch (_) {}

  // Structured extraction if request.extract is present
  if (request.extract && typeof request.extract === "object") {
    const res = {};
    for (const [key, selector] of Object.entries(request.extract)) {
      try {
        const el = document.querySelector(selector);
        res[key] = el ? (el.innerText || el.textContent || "").trim() : null;
      } catch (_) {
        res[key] = null;
      }
    }
    out.extracted = res;
  }

  // Markdown extraction if request.markdown is true
  if (request.markdown) {
    try {
      const container = document.querySelector("article, main, #content, [role='main']") || document.body;
      const clone = container.cloneNode(true);
      const drop = clone.querySelectorAll("script, style, noscript, nav, footer, header, aside, [aria-hidden='true']");
      drop.forEach((node) => node.remove());

      function nodeToMd(node) {
        if (!node) return "";
        if (node.nodeType === 3) return node.textContent.replace(/\s+/g, " ");
        if (node.nodeType !== 1) return "";
        const tag = node.tagName.toLowerCase();
        let kids = "";
        for (const child of node.childNodes) kids += nodeToMd(child);
        kids = kids.trim();
        if (!kids) return "";
        if (tag === "h1") return "\n# " + kids + "\n";
        if (tag === "h2") return "\n## " + kids + "\n";
        if (tag === "h3") return "\n### " + kids + "\n";
        if (tag === "h4" || tag === "h5" || tag === "h6") return "\n#### " + kids + "\n";
        if (tag === "p") return "\n\n" + kids + "\n\n";
        if (tag === "li") return "\n- " + kids;
        if (tag === "blockquote") return "\n> " + kids + "\n";
        if (tag === "code") return "`" + kids + "`";
        if (tag === "pre") return "\n```\n" + kids + "\n```\n";
        if (tag === "a" && node.href) return "[" + kids + "](" + node.href + ")";
        if (tag === "strong" || tag === "b") return "**" + kids + "**";
        if (tag === "em" || tag === "i") return "*" + kids + "*";
        return kids;
      }

      out.markdown = nodeToMd(clone).replace(/\n{3,}/g, "\n\n").trim();
    } catch (_) {}
  }

  // Links only: a[href] with an http(s) address, as the browser resolved it.
  // Nothing is clicked, submitted or run.
  const seen = new Set();
  for (const anchor of document.querySelectorAll("a[href]")) {
    const href = anchor.href;
    if (typeof href !== "string" || !/^https?:/i.test(href)) continue;
    const bare = href.split("#")[0];
    if (seen.has(bare)) continue;
    if (out.links.length >= request.max_links) {
      out.truncated = true;
      break;
    }
    seen.add(bare);
    out.links.push(bare);
  }
  return out;
}
