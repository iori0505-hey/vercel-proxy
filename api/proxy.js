// Vercel Serverless Function (Node.js)
const dns = require("node:dns").promises;

function isPrivateHost(host) {
  const h = host.toLowerCase();
  if (h === "localhost" || h.endsWith(".local") || h.endsWith(".internal")) return true;
  if (h === "::1" || h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80")) return true;
  const m = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) {
    const a = Number(m[1]), b = Number(m[2]);
    return a === 10 || a === 127 || a === 0 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168);
  }
  return false;
}

async function resolvesToPrivate(host) {
  try {
    const addrs = await dns.lookup(host, { all: true });
    return addrs.some((a) => isPrivateHost(a.address));
  } catch {
    return false;
  }
}

function toProxy(base, link) {
  try {
    if (/^(data:|javascript:|mailto:|tel:|#)/i.test(link)) return link;
    return "/proxy?url=" + encodeURIComponent(new URL(link, base).href);
  } catch {
    return link;
  }
}

function rewriteHtml(html, base) {
  // JavaScriptを除去して静的ページとして表示する
  html = html.replace(/<script\b[\s\S]*?<\/script>/gi, "");
  html = html.replace(/<script\b[^>]*\/>/gi, "");
  // href / src / action / poster / data-src を書き換え
  html = html.replace(
    /(\s(?:href|src|action|poster|data-src)\s*=\s*)(["'])(.*?)\2/gi,
    (_m, attr, q, val) => `${attr}${q}${toProxy(base, val)}${q}`
  );
  // srcset を書き換え
  html = html.replace(/(\ssrcset\s*=\s*)(["'])(.*?)\2/gi, (_m, attr, q, val) => {
    const out = val
      .split(",")
      .map((part) => {
        const [u, ...rest] = part.trim().split(/\s+/);
        return [toProxy(base, u), ...rest].join(" ");
      })
      .join(", ");
    return `${attr}${q}${out}${q}`;
  });
  // <style> と style="" 内の url() を書き換え
  html = html.replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, (m) => rewriteCss(m, base));
  return html;
}

function rewriteCss(css, base) {
  return css.replace(/url\(\s*(["']?)(.*?)\1\s*\)/gi, (_m, q, val) => {
    if (/^data:/i.test(val)) return _m;
    return `url(${q}${toProxy(base, val)}${q})`;
  });
}

module.exports = async (req, res) => {
  let target;
  try {
    target = new URL(req.query.url || "");
    if (!["http:", "https:"].includes(target.protocol)) throw new Error();
  } catch {
    return res.status(400).send("無効なURLです");
  }

  if (isPrivateHost(target.hostname) || (await resolvesToPrivate(target.hostname))) {
    return res.status(403).send("このアドレスにはアクセスできません");
  }

  let upstream;
  try {
    upstream = await fetch(target.href, {
      headers: {
        "user-agent": req.headers["user-agent"] || "Mozilla/5.0",
        accept: req.headers["accept"] || "*/*",
        "accept-language": req.headers["accept-language"] || "ja,en;q=0.8",
      },
      redirect: "manual",
    });
  } catch {
    return res.status(502).send("取得に失敗しました");
  }

  // リダイレクトもプロキシ経由にする
  if ([301, 302, 303, 307, 308].includes(upstream.status)) {
    const loc = upstream.headers.get("location");
    if (loc) return res.redirect(302, toProxy(target.href, loc));
  }

  const skip = new Set([
    "content-security-policy", "x-frame-options", "content-encoding",
    "content-length", "set-cookie", "transfer-encoding", "connection",
  ]);
  upstream.headers.forEach((v, k) => {
    if (!skip.has(k.toLowerCase())) res.setHeader(k, v);
  });

  const type = upstream.headers.get("content-type") || "";
  res.status(upstream.status);

  if (type.includes("text/html")) {
    const html = await upstream.text();
    return res.send(rewriteHtml(html, target.href));
  }
  if (type.includes("text/css")) {
    const css = await upstream.text();
    return res.send(rewriteCss(css, target.href));
  }
  const buf = Buffer.from(await upstream.arrayBuffer());
  return res.send(buf);
};
