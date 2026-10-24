(request) => {
  const out = {
    url: location.href,
    title: document.title || "",
    status: null,
    links: [],
    truncated: false,
    nofollow: false,
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
