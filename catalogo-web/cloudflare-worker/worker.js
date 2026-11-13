/*
 * IZAN CATALOGO - Worker de fotos en Cloudflare R2
 *
 * Rutas:
 *   PUT  /upload/<punto>/<ref>/<archivo>.jpg   -> sube una foto (requiere sesión de Supabase)
 *   POST /delete  {"keys":[...]}               -> borra fotos (requiere sesión de Supabase)
 *   GET  /f/<punto>/<ref>/<archivo>.jpg        -> sirve la foto públicamente (con caché)
 *
 * Permisos (iguales a los que tenía el bucket de Supabase):
 *   - El administrador puede subir/borrar en cualquier punto.
 *   - El usuario de un punto solo puede subir/borrar dentro de la carpeta de su punto (slug).
 *
 * Variables del Worker:
 *   FOTOS            -> binding al bucket R2
 *   SUPABASE_URL     -> https://xxxx.supabase.co
 *   SUPABASE_KEY     -> anon key de Supabase (la misma de index.html)
 *   ALLOWED_ORIGINS  -> opcional, dominios de tu página separados por coma (ej. https://izan.vercel.app). "*" = cualquiera
 */

const KEY_RE = /^[a-z0-9-]+\/[0-9a-f-]{36}\/[a-z0-9]+(_t)?\.jpg$/;
const MAX_BYTES = 8 * 1024 * 1024;

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const cors = corsHeaders(req, env);

    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

    try {
      if ((req.method === "GET" || req.method === "HEAD") && url.pathname.startsWith("/f/")) {
        return await serve(req, env, ctx, decodeURIComponent(url.pathname.slice(3)));
      }
      if (req.method === "PUT" && url.pathname.startsWith("/upload/")) {
        const key = decodeURIComponent(url.pathname.slice(8));
        if (!KEY_RE.test(key)) throw httpErr(400, "Nombre de archivo inválido");
        const perm = await permiso(req, env);
        checkFolder(perm, key);
        const type = req.headers.get("Content-Type") || "";
        if (type !== "image/jpeg") throw httpErr(415, "Solo se aceptan imágenes JPEG");
        const len = +req.headers.get("Content-Length") || 0;
        if (len > MAX_BYTES) throw httpErr(413, "La imagen es demasiado grande");
        const body = await req.arrayBuffer();
        if (body.byteLength === 0 || body.byteLength > MAX_BYTES) throw httpErr(413, "Tamaño de imagen inválido");
        await env.FOTOS.put(key, body, {
          httpMetadata: { contentType: "image/jpeg", cacheControl: "public, max-age=31536000, immutable" },
        });
        return json({ ok: true, key }, 200, cors);
      }
      if (req.method === "POST" && url.pathname === "/delete") {
        const perm = await permiso(req, env);
        const { keys } = await req.json().catch(() => ({}));
        if (!Array.isArray(keys) || keys.length > 1000) throw httpErr(400, "Lista de archivos inválida");
        const ok = keys.filter((k) => typeof k === "string" && KEY_RE.test(k));
        ok.forEach((k) => checkFolder(perm, k));
        if (ok.length) await env.FOTOS.delete(ok);
        return json({ ok: true, deleted: ok.length }, 200, cors);
      }
      return json({ error: "No encontrado" }, 404, cors);
    } catch (e) {
      return json({ error: e.message || String(e) }, e.status || 500, cors);
    }
  },
};

async function serve(req, env, ctx, key) {
  const pub = { "Access-Control-Allow-Origin": "*" };
  if (!KEY_RE.test(key)) return new Response("No encontrado", { status: 404, headers: pub });
  const cache = caches.default;
  if (req.method === "GET") {
    const hit = await cache.match(req);
    if (hit) return hit;
  }
  const obj = req.method === "HEAD" ? await env.FOTOS.head(key) : await env.FOTOS.get(key);
  if (!obj) return new Response("No encontrado", { status: 404, headers: pub });
  const h = new Headers(pub);
  obj.writeHttpMetadata(h);
  h.set("Content-Type", "image/jpeg");
  h.set("Cache-Control", "public, max-age=31536000, immutable");
  h.set("ETag", obj.httpEtag);
  if (req.method === "HEAD") return new Response(null, { headers: h });
  const res = new Response(obj.body, { headers: h });
  ctx.waitUntil(cache.put(req, res.clone()));
  return res;
}

/* Valida la sesión de Supabase y devuelve si es admin o el slug de su punto. */
async function permiso(req, env) {
  const auth = req.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) throw httpErr(401, "Falta iniciar sesión");
  const base = env.SUPABASE_URL.replace(/\/$/, "");
  const h = { apikey: env.SUPABASE_KEY, Authorization: auth };

  const u = await fetch(base + "/auth/v1/user", { headers: h });
  if (!u.ok) throw httpErr(401, "Sesión inválida o expirada");

  const ad = await getJson(base + "/rest/v1/admins?select=user_id", h);
  if (ad.length) return { admin: true };

  const pf = await getJson(base + "/rest/v1/perfiles?select=punto", h);
  if (!pf.length) throw httpErr(403, "Tu usuario no tiene punto asignado");
  const pt = await getJson(base + "/rest/v1/puntos?select=slug&nombre=eq." + encodeURIComponent(pf[0].punto), h);
  if (!pt.length || !pt[0].slug) throw httpErr(403, "Punto no encontrado");
  return { admin: false, slug: pt[0].slug };
}

function checkFolder(perm, key) {
  if (perm.admin) return;
  if (key.split("/")[0] !== perm.slug) throw httpErr(403, "No puedes modificar fotos de otro punto");
}

async function getJson(u, headers) {
  const r = await fetch(u, { headers });
  if (!r.ok) throw httpErr(502, "No se pudo verificar el usuario en Supabase");
  const d = await r.json();
  return Array.isArray(d) ? d : [];
}

function corsHeaders(req, env) {
  const origin = req.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGINS || "*").split(",").map((s) => s.trim()).filter(Boolean);
  const allow = allowed.includes("*") ? "*" : allowed.includes(origin) ? origin : allowed[0] || "";
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "GET,HEAD,PUT,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Authorization,Content-Type",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...headers, "Content-Type": "application/json; charset=utf-8" },
  });
}

function httpErr(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}
