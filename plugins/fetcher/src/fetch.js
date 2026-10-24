async function (request) {
  "use strict";
  // Fetches request.url as the page would, with the page's cookies, and reads
  // at most request.max_bytes of the body. Pure: it touches nothing else.
  const response = await fetch(request.url, {
    credentials: "include",
    redirect: "follow",
  });
  const mime = (response.headers.get("content-type") || "")
    .split(";")[0]
    .trim()
    .toLowerCase();
  const chunks = [];
  let total = 0;
  let truncated = false;
  if (response.body) {
    const reader = response.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (total + value.length > request.max_bytes) {
        chunks.push(value.subarray(0, request.max_bytes - total));
        total = request.max_bytes;
        truncated = true;
        await reader.cancel();
        break;
      }
      chunks.push(value);
      total += value.length;
    }
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return {
    url: response.url,
    status: response.status,
    mime: mime,
    text: new TextDecoder("utf-8").decode(bytes),
    truncated: truncated,
  };
}
