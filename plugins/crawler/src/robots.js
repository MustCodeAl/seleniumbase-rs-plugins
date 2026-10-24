() => {
  let status = null;
  try {
    const nav = performance.getEntriesByType("navigation")[0];
    if (nav && typeof nav.responseStatus === "number" && nav.responseStatus > 0) {
      status = nav.responseStatus;
    }
  } catch (_) {}
  const body = document.body;
  const text = body ? body.innerText || "" : "";
  return { url: location.href, status, text: text.slice(0, 524288) };
}
