// 드림 200일 홈페이지 — 서버 쪽 코드 (Netlify Functions + Netlify Blobs)
import { getStore } from "@netlify/blobs";
import { createHmac, createHash, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

export const config = { path: "/api/*" };

const TYPES = ["tribute", "art", "poem", "letter"];
const TITLE_FONTS = ["batang", "myeongjo", "dodum", "jua", "hanna", "pen", "gaegu", "dokdo", "cormorant"];
const COOKIE_SITE = "tb_site";
const COOKIE_OWNER = "tb_owner";
const SITE_TTL = 60 * 60 * 24 * 30; // 30일
const OWNER_TTL = 60 * 60 * 12; // 12시간

const posts = () => getStore({ name: "posts", consistency: "strong" });
const images = () => getStore({ name: "images", consistency: "strong" });
const meta = () => getStore({ name: "meta", consistency: "strong" });

const SITE_PASSWORD = () => process.env.SITE_PASSWORD || "0505";
const OWNER_PASSWORD = () => process.env.OWNER_PASSWORD || "";
const SECRET = () => process.env.SESSION_SECRET || "";

/* ---------- 작은 도우미들 ---------- */
function respond(data, status = 200, cookies = []) {
  const h = new Headers({ "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  for (const c of cookies) h.append("set-cookie", c);
  return new Response(JSON.stringify(data), { status, headers: h });
}
const fail = (msg, status = 400) => respond({ error: msg }, status);
const cookie = (name, val, ttl) => `${name}=${val}; Path=/; Max-Age=${ttl}; HttpOnly; Secure; SameSite=Lax`;
const sha = (s) => createHash("sha256").update(String(s)).digest();
const safeEqual = (a, b) => timingSafeEqual(sha(a), sha(b));
const newId = () => Date.now().toString(36) + randomBytes(5).toString("hex");
const ID_RE = /^[a-z0-9]{8,40}$/;

function parseCookies(header) {
  const out = {};
  for (const part of (header || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
function sign(kind, ttl) {
  const exp = Math.floor(Date.now() / 1000) + ttl;
  const p = `${kind}.${exp}`;
  const sig = createHmac("sha256", SECRET()).update(p).digest("base64url");
  return `${p}.${sig}`;
}
function verifyToken(token, kind) {
  if (!token) return false;
  const [k, exp, sig] = token.split(".");
  if (k !== kind || !exp || !sig || Number(exp) < Date.now() / 1000) return false;
  const good = createHmac("sha256", SECRET()).update(`${k}.${exp}`).digest("base64url");
  return safeEqual(sig, good);
}

/* ---------- 비밀번호 틀림 횟수 제한 (무작위 대입 방지) ---------- */
const ipKey = (kind, ip) => `rl/${kind}/${createHash("sha256").update(ip).digest("hex").slice(0, 24)}`;
async function isLocked(kind, ip) {
  const r = await meta().get(ipKey(kind, ip), { type: "json" });
  return !!(r && r.until && r.until > Date.now());
}
async function recordFail(kind, ip) {
  const now = Date.now();
  let r = (await meta().get(ipKey(kind, ip), { type: "json" })) || { n: 0, t: now };
  if (now - r.t > 10 * 60 * 1000) r = { n: 0, t: now };
  r.n += 1;
  if (r.n >= 8) r.until = now + 15 * 60 * 1000;
  await meta().setJSON(ipKey(kind, ip), r);
}
const clearFails = (kind, ip) => meta().delete(ipKey(kind, ip)).catch(() => {});

/* ---------- 글 비밀번호 ---------- */
function hashPw(pw) {
  const salt = randomBytes(16).toString("hex");
  return { salt, hash: scryptSync(pw, salt, 32).toString("hex") };
}
function checkPw(post, pw) {
  if (!post.pw || !pw) return false;
  const h = scryptSync(String(pw), post.pw.salt, 32);
  return timingSafeEqual(h, Buffer.from(post.pw.hash, "hex"));
}
const publicPost = (p) => {
  const { pw, ...rest } = p;
  return rest;
};

/* ---------- 입력 검사 ---------- */
const clean = (v, max) => String(v ?? "").replace(/\r\n/g, "\n").trim().slice(0, max);
function validatePost(b) {
  const type = String(b.type || "");
  if (!TYPES.includes(type)) return { error: "글 종류가 올바르지 않아요." };
  const nickname = clean(b.nickname, 20);
  const title = clean(b.title, 80);
  const body = clean(b.body, 20000);
  const body2 = clean(b.body2, 20000);
  const imageId = b.imageId ? String(b.imageId) : "";
  if (!nickname) return { error: "닉네임을 입력해 주세요." };
  if (!title) return { error: "제목을 입력해 주세요." };
  if (type !== "art" && !body) return { error: "내용을 입력해 주세요." };
  if (imageId && !ID_RE.test(imageId)) return { error: "이미지 정보가 올바르지 않아요." };
  if (type === "art" && !imageId) return { error: "그림 이미지를 올려 주세요." };
  return { data: { type, nickname, title, body, body2, imageId } };
}

/* ---------- 설정(꾸미기·플레이리스트) ---------- */
const DEFAULT_SETTINGS = { bg: null, accent: "#1f68a8", cardAlpha: 0.78, titleFont: "batang", stickers: [], playlist: [] };
async function getSettings() {
  const s = (await meta().get("settings", { type: "json" })) || {};
  return { ...DEFAULT_SETTINGS, ...s };
}
function sanitizeSettings(b) {
  const out = {};
  if ("bg" in b) out.bg = b.bg && ID_RE.test(String(b.bg)) ? String(b.bg) : null;
  if ("accent" in b) out.accent = /^#[0-9a-fA-F]{6}$/.test(String(b.accent)) ? String(b.accent) : DEFAULT_SETTINGS.accent;
  if ("cardAlpha" in b) out.cardAlpha = Math.min(1, Math.max(0.3, Number(b.cardAlpha) || 0.78));
  if ("titleFont" in b) out.titleFont = TITLE_FONTS.includes(b.titleFont) ? b.titleFont : "batang";
  if (Array.isArray(b.stickers)) {
    out.stickers = b.stickers.slice(0, 30).flatMap((s) => {
      if (!s || !ID_RE.test(String(s.img))) return [];
      const num = (v, lo, hi, d) => Math.min(hi, Math.max(lo, Number(v) || d));
      return [{ id: String(s.id || newId()).replace(/[^a-z0-9]/gi, "").slice(0, 24) || newId(), img: String(s.img), x: num(s.x, 0, 100, 10), y: num(s.y, 0, 6000, 100), w: num(s.w, 20, 800, 160) }];
    });
  }
  return out;
}
const YT_RE = /(?:youtu\.be\/|[?&]v=|\/shorts\/|\/embed\/|\/live\/)([A-Za-z0-9_-]{11})/;
async function youtubeTitle(vid) {
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 4000);
    const r = await fetch(`https://www.youtube.com/oembed?url=${encodeURIComponent("https://www.youtube.com/watch?v=" + vid)}&format=json`, { signal: ctl.signal });
    clearTimeout(t);
    if (!r.ok) return null;
    const j = await r.json();
    return clean(j.title, 120) || null;
  } catch {
    return null;
  }
}

/* ---------- 요청 처리 ---------- */
export default async (req, context) => {
  if (!SECRET()) return fail("서버 설정이 필요해요: SESSION_SECRET 환경변수를 등록해 주세요.", 500);

  const url = new URL(req.url);
  const parts = url.pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean);
  const [r0, r1, r2] = parts;
  const method = req.method;
  const cookies = parseCookies(req.headers.get("cookie"));
  const isSite = verifyToken(cookies[COOKIE_SITE], "site");
  const isOwner = isSite && verifyToken(cookies[COOKIE_OWNER], "owner");
  const ip = context?.ip || req.headers.get("x-nf-client-connection-ip") || "unknown";
  const body = async () => (await req.json().catch(() => ({}))) || {};

  try {
    if (r0 === "me") return respond({ site: isSite, owner: isOwner, ownerEnabled: !!OWNER_PASSWORD() });

    if (r0 === "login" && method === "POST") {
      if (await isLocked("login", ip)) return fail("시도가 너무 많아요. 잠시 뒤에 다시 해 주세요.", 429);
      const b = await body();
      if (safeEqual(String(b.password || ""), SITE_PASSWORD())) {
        await clearFails("login", ip);
        return respond({ ok: true }, 200, [cookie(COOKIE_SITE, sign("site", SITE_TTL), SITE_TTL)]);
      }
      await recordFail("login", ip);
      return fail("비밀번호가 맞지 않아요.", 401);
    }

    if (r0 === "logout" && method === "POST") {
      return respond({ ok: true }, 200, [cookie(COOKIE_SITE, "", 0), cookie(COOKIE_OWNER, "", 0)]);
    }

    if (!isSite) return fail("먼저 비밀번호를 입력해 주세요.", 401);

    if (r0 === "owner-login" && method === "POST") {
      if (!OWNER_PASSWORD()) return fail("주인 비밀번호(OWNER_PASSWORD)가 아직 설정되지 않았어요.");
      if (await isLocked("owner", ip)) return fail("시도가 너무 많아요. 잠시 뒤에 다시 해 주세요.", 429);
      const b = await body();
      if (safeEqual(String(b.password || ""), OWNER_PASSWORD())) {
        await clearFails("owner", ip);
        return respond({ ok: true }, 200, [cookie(COOKIE_OWNER, sign("owner", OWNER_TTL), OWNER_TTL)]);
      }
      await recordFail("owner", ip);
      return fail("주인 비밀번호가 맞지 않아요.", 401);
    }
    if (r0 === "owner-logout" && method === "POST") return respond({ ok: true }, 200, [cookie(COOKIE_OWNER, "", 0)]);

    /* ----- 글 ----- */
    if (r0 === "posts") {
      if (!r1) {
        if (method === "GET") {
          const { blobs } = await posts().list({ prefix: "p/" });
          const items = await Promise.all(blobs.slice(0, 600).map((b) => posts().get(b.key, { type: "json" })));
          const list = items.filter(Boolean).map(publicPost).sort((a, b) => b.createdAt - a.createdAt);
          return respond({ posts: list });
        }
        if (method === "POST") {
          const b = await body();
          const v = validatePost(b);
          if (v.error) return fail(v.error);
          const pw = String(b.password || "");
          if (pw.length < 4 || pw.length > 40) return fail("글 비밀번호는 4~40자로 정해 주세요.");
          const id = newId();
          const now = Date.now();
          const post = { id, ...v.data, createdAt: now, updatedAt: now, pw: hashPw(pw) };
          await posts().setJSON("p/" + id, post);
          return respond({ post: publicPost(post) }, 201);
        }
        return fail("지원하지 않는 요청이에요.", 405);
      }

      if (!ID_RE.test(r1)) return fail("글을 찾을 수 없어요.", 404);
      const key = "p/" + r1;
      const post = await posts().get(key, { type: "json" });
      if (!post) return fail("글을 찾을 수 없어요.", 404);

      // 비밀번호(또는 주인 권한) 확인
      const authorize = async (pw) => {
        if (isOwner) return true;
        if (await isLocked("post", ip)) return "locked";
        if (checkPw(post, pw)) {
          await clearFails("post", ip);
          return true;
        }
        await recordFail("post", ip);
        return false;
      };

      if (r2 === "verify" && method === "POST") {
        const b = await body();
        const ok = await authorize(String(b.password || ""));
        if (ok === "locked") return fail("시도가 너무 많아요. 잠시 뒤에 다시 해 주세요.", 429);
        return ok ? respond({ ok: true, owner: isOwner }) : fail("비밀번호가 맞지 않아요.", 403);
      }
      if (method === "GET") return respond({ post: publicPost(post) });

      if (method === "PUT") {
        const b = await body();
        const ok = await authorize(String(b.password || ""));
        if (ok === "locked") return fail("시도가 너무 많아요. 잠시 뒤에 다시 해 주세요.", 429);
        if (!ok) return fail("비밀번호가 맞지 않아요.", 403);
        const v = validatePost({ ...b, type: post.type });
        if (v.error) return fail(v.error);
        if (post.imageId && post.imageId !== v.data.imageId) await images().delete(post.imageId).catch(() => {});
        const updated = { ...post, ...v.data, updatedAt: Date.now() };
        await posts().setJSON(key, updated);
        return respond({ post: publicPost(updated) });
      }

      if (method === "DELETE") {
        const b = await body();
        const ok = await authorize(String(b.password || ""));
        if (ok === "locked") return fail("시도가 너무 많아요. 잠시 뒤에 다시 해 주세요.", 429);
        if (!ok) return fail("비밀번호가 맞지 않아요.", 403);
        if (post.imageId) await images().delete(post.imageId).catch(() => {});
        await posts().delete(key);
        return respond({ ok: true });
      }
      return fail("지원하지 않는 요청이에요.", 405);
    }

    /* ----- 이미지 ----- */
    if (r0 === "upload" && method === "POST") {
      const kind = url.searchParams.get("kind") || "post";
      if (kind === "decor" && !isOwner) return fail("꾸미기 이미지는 주인만 올릴 수 있어요.", 403);
      const type = (req.headers.get("content-type") || "").split(";")[0].trim();
      if (!/^image\/(jpeg|png|webp|gif)$/.test(type)) return fail("JPG, PNG, WEBP, GIF 이미지만 올릴 수 있어요.", 415);
      const buf = await req.arrayBuffer();
      if (buf.byteLength > 5 * 1024 * 1024) return fail("이미지가 너무 커요. (5MB 이하)", 413);
      if (buf.byteLength < 100) return fail("이미지가 비어 있어요.");
      const id = newId();
      await images().set(id, buf, { metadata: { contentType: type } });
      return respond({ id, url: `/api/img/${id}` }, 201);
    }
    if (r0 === "img" && r1 && method === "GET") {
      if (!ID_RE.test(r1)) return fail("not found", 404);
      const r = await images().getWithMetadata(r1, { type: "arrayBuffer" });
      if (!r) return fail("not found", 404);
      return new Response(r.data, {
        headers: { "content-type": r.metadata?.contentType || "image/jpeg", "cache-control": "private, max-age=31536000, immutable", "x-content-type-options": "nosniff" },
      });
    }

    /* ----- 꾸미기 설정 & 플레이리스트 ----- */
    if (r0 === "settings") {
      if (method === "GET") return respond({ settings: await getSettings() });
      if (method === "PUT") {
        if (!isOwner) return fail("주인만 바꿀 수 있어요.", 403);
        const cur = await getSettings();
        const next = { ...cur, ...sanitizeSettings(await body()) };
        await meta().setJSON("settings", next);
        return respond({ settings: next });
      }
    }
    if (r0 === "playlist") {
      if (!isOwner) return fail("주인만 바꿀 수 있어요.", 403);
      const cur = await getSettings();
      if (method === "POST") {
        const b = await body();
        const m = String(b.url || "").match(YT_RE);
        if (!m) return fail("유튜브 영상 링크를 넣어 주세요. (재생목록 링크는 안 돼요)");
        const vid = m[1];
        if (cur.playlist.some((t) => t.vid === vid)) return fail("이미 들어 있는 곡이에요.");
        if (cur.playlist.length >= 100) return fail("곡은 최대 100개까지 넣을 수 있어요.");
        const title = clean(b.title, 120) || (await youtubeTitle(vid)) || `곡 ${cur.playlist.length + 1}`;
        cur.playlist.push({ vid, title });
        await meta().setJSON("settings", cur);
        return respond({ settings: cur }, 201);
      }
      if (method === "DELETE" && r1) {
        cur.playlist = cur.playlist.filter((t) => t.vid !== r1);
        await meta().setJSON("settings", cur);
        return respond({ settings: cur });
      }
    }

    return fail("not found", 404);
  } catch (e) {
    console.error(e);
    return fail("서버에서 문제가 생겼어요. 잠시 뒤에 다시 해 주세요.", 500);
  }
};
