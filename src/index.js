const PACKAGES = {
  basic:    { name: "P12 Basic 1 Year",        price: 6 },
  standard: { name: "P12 Standard 1 Year",     price: 8 },
  premium:  { name: "P12 Premium Plan 1 Year", price: 19.99 }
};

// Static Paymento payment links, one per package.
const PAYMENT_LINKS = {
  basic:    "https://app.paymento.io/payment-link/844a5734d21d4eff8e8595a7088f3cce",
  standard: "https://app.paymento.io/payment-link/7373a74981de4d039cb5cf9b42eb541c",
  premium:  "https://YOUR-PAY-LINK-PREMIUM"
};

const PBKDF2_ITERATIONS = 100000;
const TOKEN_HOURS = 12;
const enc = new TextEncoder();
const dec = new TextDecoder();

// Used when the email doesn't exist, so login takes the same time either way.
const DUMMY_HASH = "pbkdf2$100000$" + "00".repeat(16) + "$" + "00".repeat(32);

// ---------- Responses ----------
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

// ---------- Encoding helpers ----------
function toHex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex) {
  return Uint8Array.from(hex.match(/../g) || [], h => parseInt(h, 16));
}

function b64urlEncode(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(str) {
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

// Compares two byte arrays in constant time.
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ---------- Tokens (admin login) ----------
function hmacKey(secret, usages) {
  return crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, usages
  );
}

async function signToken(userId, secret) {
  const payload = b64urlEncode(enc.encode(JSON.stringify({
    sub: userId,
    exp: Date.now() + TOKEN_HOURS * 3600 * 1000
  })));
  const key = await hmacKey(secret, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(payload)));
  return `${payload}.${b64urlEncode(sig)}`;
}

async function verifyToken(token, secret) {
  try {
    const [payload, sig] = String(token || "").split(".");
    if (!payload || !sig) return null;
    const key = await hmacKey(secret, ["verify"]);
    const valid = await crypto.subtle.verify("HMAC", key, b64urlDecode(sig), enc.encode(payload));
    if (!valid) return null;
    const data = JSON.parse(dec.decode(b64urlDecode(payload)));
    return data.exp > Date.now() ? data.sub : null;
  } catch {
    return null;
  }
}

// ---------- Passwords ----------
async function derivePassword(password, salt, iterations) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" }, key, 256
  );
  return new Uint8Array(bits);
}

async function verifyPassword(password, stored) {
  const [scheme, iterations, saltHex, hashHex] = String(stored).split("$");
  if (scheme !== "pbkdf2") return false;
  const hash = await derivePassword(password, fromHex(saltHex), Number(iterations));
  return bytesEqual(hash, fromHex(hashHex));
}

// ---------- Input checks ----------
function normalizeUdid(v) {
  const s = String(v || "").trim().toUpperCase();
  return /^[A-Z0-9-]{20,50}$/.test(s) ? s : null;
}

function normalizeEmail(v) {
  const s = String(v || "").trim().toLowerCase();
  return s.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s) ? s : null;
}

function normalizeRef(v) {
  const s = String(v || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  return s.length === 8 ? s : null;
}

function newRef() {
  return toHex(crypto.getRandomValues(new Uint8Array(4))).toUpperCase();
}

// Accepts YYYY-MM-DD or an ISO date. Blank means one year from now.
function parseExpiry(v) {
  if (!v) return new Date(Date.now() + 365 * 86400000).toISOString();
  const d = new Date(String(v));
  if (isNaN(d) || d.getTime() < Date.now() - 86400000) return null;
  return d.toISOString();
}

function stateOf(o) {
  if (o.delivered_at) return "delivered";
  if (o.status === "paid") return "delivering";
  return "pending";
}

// ---------- Database helpers ----------
async function insertOrder(env, { pkg, udid, email }) {
  const id = crypto.randomUUID();
  for (let attempt = 0; attempt < 5; attempt++) {
    const ref = newRef();
    try {
      await env.DB.prepare(
        "INSERT INTO orders (id, ref, package_key, udid, delivery_email) VALUES (?, ?, ?, ?, ?)"
      ).bind(id, ref, pkg, udid, email).run();
      return ref;
    } catch (err) {
      if (!String(err.message).includes("UNIQUE")) throw err;
    }
  }
  throw new Error("Could not create an order reference.");
}

// Moves an order from pending to paid. Runs once; repeat calls do nothing.
async function markPaid(env, orderId, paymentId) {
  const r = await env.DB.prepare(
    "UPDATE orders SET status = 'paid', paid_at = CURRENT_TIMESTAMP, payment_id = ? WHERE id = ? AND status = 'pending'"
  ).bind(paymentId || null, orderId).run();
  return r.meta.changes === 1;
}

// ---------- Paymento ----------
async function paymentoVerify(env, token) {
  const r = await fetch("https://api.paymento.io/v1/payment/verify", {
    method: "POST",
    headers: {
      "Api-key": env.PAYMENTO_API_KEY,
      "Content-Type": "application/json",
      "Accept": "text/plain"
    },
    body: JSON.stringify({ token })
  });
  const data = await r.json().catch(() => ({}));
  if (!data.success || !data.body) return null;
  // CHECK: confirm the field that shows "Paid" in the verify response.
  return {
    orderId: String(data.body.orderId || ""),
    paid: String(data.body.status || "").toLowerCase() === "paid"
  };
}

// ---------- Admin guard ----------
async function requireAdmin(request, env) {
  const header = request.headers.get("Authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return json({ error: "Please log in." }, 401);

  const userId = await verifyToken(token, env.JWT_SECRET);
  if (!userId) return json({ error: "Your session has expired. Please log in again." }, 401);

  const user = await env.DB.prepare("SELECT is_admin FROM users WHERE id = ?").bind(userId).first();
  if (!user || user.is_admin !== 1) return json({ error: "This account is not an admin." }, 403);
  return null;
}

// ---------- Webhook ----------
async function handleWebhook(request, env) {
  const bodyBytes = new Uint8Array(await request.arrayBuffer());

  const sig = request.headers.get("x-hmac-sha256-signature") || request.headers.get("x-paymento-signature") || "";
  const key = await hmacKey(env.PAYMENTO_WEBHOOK_SECRET, ["sign"]);
  const expected = toHex(new Uint8Array(await crypto.subtle.sign("HMAC", key, bodyBytes)));
  if (!bytesEqual(enc.encode(sig), enc.encode(expected))) return new Response(null, { status: 401 });

  let cb;
  try {
    cb = JSON.parse(dec.decode(bodyBytes));
  } catch {
    return new Response(null, { status: 400 });
  }

  const token = String(cb.Token || "");
  const orderId = String(cb.OrderId || "");
  if (!token || !orderId) return new Response(null, { status: 400 });

  const order = await env.DB.prepare("SELECT id, payment_token FROM orders WHERE id = ?").bind(orderId).first();
  if (!order || order.payment_token !== token) return new Response(null, { status: 200 });

  // Never trust the webhook body alone. Confirm with Paymento's API.
  const check = await paymentoVerify(env, token);
  if (check && check.paid && check.orderId === orderId) {
    await markPaid(env, orderId, String(cb.PaymentId || ""));
  }
  return new Response(null, { status: 200 });
}

// ---------- Admin login ----------
async function handleLogin(request, env) {
  const body = await request.json().catch(() => ({}));
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  const user = await env.DB.prepare("SELECT id, password_hash FROM users WHERE email = ?").bind(email).first();
  const ok = await verifyPassword(password, user ? user.password_hash : DUMMY_HASH);
  if (!user || !ok) return json({ error: "Wrong email or password." }, 401);

  return json({ token: await signToken(user.id, env.JWT_SECRET) });
}

// ---------- Customer: place an order ----------
async function handlePlaceOrder(request, env) {
  const body = await request.json().catch(() => ({}));

  const pkg = String(body.package || "");
  if (!Object.prototype.hasOwnProperty.call(PACKAGES, pkg)) {
    return json({ error: "Unknown package." }, 400);
  }

  const link = PAYMENT_LINKS[pkg];
  if (!link || link.includes("YOUR-")) {
    return json({ error: "This package is not available yet." }, 503);
  }

  const udid = normalizeUdid(body.udid);
  if (!udid) return json({ error: "Please enter a valid device UDID." }, 400);

  const email = normalizeEmail(body.delivery_email);
  if (!email) return json({ error: "Please enter a valid delivery email." }, 400);

  const ref = await insertOrder(env, { pkg, udid, email });
  return json({ ref, checkoutUrl: link }, 201);
}

// ---------- Customer: check one order ----------
async function handleLookup(request, env) {
  const body = await request.json().catch(() => ({}));
  const ref = normalizeRef(body.ref);
  const email = normalizeEmail(body.email);
  if (!ref || !email) {
    return json({ error: "Enter your 8-character order reference and delivery email." }, 400);
  }

  const o = await env.DB.prepare(
    "SELECT ref, package_key, status, delivery_email, created_at, delivered_at FROM orders WHERE ref = ?"
  ).bind(ref).first();

  // Same message whether the reference or the email is wrong.
  if (!o || o.delivery_email !== email) {
    return json({ error: "No order found with that reference and email." }, 404);
  }

  return json({
    ref: o.ref,
    package_name: PACKAGES[o.package_key]?.name || o.package_key,
    state: stateOf(o),
    created_at: o.created_at,
    delivered_at: o.delivered_at
  });
}

// ---------- Customer: status for several orders (Orders tab) ----------
async function handleStatus(request, env) {
  const body = await request.json().catch(() => ({}));
  const list = Array.isArray(body.orders) ? body.orders.slice(0, 20) : [];

  const results = await Promise.all(list.map(async item => {
    const ref = normalizeRef(item && item.ref);
    const email = normalizeEmail(item && item.email);
    if (!ref || !email) return { ref: String(item?.ref || ""), found: false };

    const o = await env.DB.prepare(
      "SELECT ref, package_key, status, delivery_email, created_at, delivered_at, expires_at FROM orders WHERE ref = ?"
    ).bind(ref).first();

    if (!o || o.delivery_email !== email) return { ref, found: false };

    return {
      ref: o.ref,
      found: true,
      package_key: o.package_key,
      package_name: PACKAGES[o.package_key]?.name || o.package_key,
      state: stateOf(o),
      created_at: o.created_at,
      delivered_at: o.delivered_at,
      expires_at: o.expires_at
    };
  }));

  return json({ results });
}

// ---------- Admin: list orders ----------
async function handleAdminList(request, env) {
  const denied = await requireAdmin(request, env);
  if (denied) return denied;

  const { results } = await env.DB.prepare(`
    SELECT id, ref, package_key, udid, delivery_email, status, payment_id,
           created_at, paid_at, delivered_at, expires_at, delivery_note
    FROM orders
    ORDER BY created_at DESC
    LIMIT 500
  `).all();

  return json({
    orders: results.map(o => ({
      ...o,
      package_name: PACKAGES[o.package_key]?.name || o.package_key,
      state: stateOf(o)
    }))
  });
}

// ---------- Admin: paid / udid / delivered ----------
async function handleAdminAction(request, env, id, action) {
  const denied = await requireAdmin(request, env);
  if (denied) return denied;

  const body = await request.json().catch(() => ({}));

  if (action === "paid") {
    const ok = await markPaid(env, id, "manual");
    return ok ? json({ ok: true }) : json({ error: "Order not found or not pending." }, 409);
  }

  if (action === "udid") {
    const udid = normalizeUdid(body.udid);
    if (!udid) return json({ error: "Invalid UDID." }, 400);
    const r = await env.DB.prepare(
      "UPDATE orders SET udid = ? WHERE id = ? AND delivered_at IS NULL"
    ).bind(udid, id).run();
    return r.meta.changes === 1
      ? json({ ok: true })
      : json({ error: "Order not found or already delivered." }, 409);
  }

  if (action === "delivered") {
    const order = await env.DB.prepare(
      "SELECT id, status, udid, delivered_at FROM orders WHERE id = ?"
    ).bind(id).first();

    if (!order) return json({ error: "Order not found." }, 404);
    if (order.status !== "paid") return json({ error: "This order has not been paid." }, 409);
    if (order.delivered_at) return json({ error: "This order is already marked delivered." }, 409);
    if (!order.udid) return json({ error: "This order has no UDID. Add one first." }, 409);

    const expiresAt = parseExpiry(body.expires_at);
    if (!expiresAt) return json({ error: "Enter a valid expiry date." }, 400);

    const note = String(body.note || "").slice(0, 300) || null;
    const r = await env.DB.prepare(`
      UPDATE orders
      SET delivered_at = CURRENT_TIMESTAMP, delivery_note = ?, expires_at = ?
      WHERE id = ? AND delivered_at IS NULL
    `).bind(note, expiresAt, id).run();

    return r.meta.changes === 1
      ? json({ ok: true })
      : json({ error: "This order is already marked delivered." }, 409);
  }

  return json({ error: "Not found." }, 404);
}

// ---------- Router ----------
export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    const method = request.method;

    try {
      if (pathname === "/api/webhooks/paymento" && method === "POST") return await handleWebhook(request, env);
      if (pathname === "/api/auth/login" && method === "POST") return await handleLogin(request, env);
      if (pathname === "/api/orders" && method === "POST") return await handlePlaceOrder(request, env);
      if (pathname === "/api/orders/lookup" && method === "POST") return await handleLookup(request, env);
      if (pathname === "/api/orders/status" && method === "POST") return await handleStatus(request, env);
      if (pathname === "/api/admin/orders" && method === "GET") return await handleAdminList(request, env);

      const admin = pathname.match(/^\/api\/admin\/orders\/([^/]+)\/(paid|udid|delivered)$/);
      if (admin && method === "POST") return await handleAdminAction(request, env, admin[1], admin[2]);

      if (pathname.startsWith("/api/")) return json({ error: "Not found." }, 404);

      return env.ASSETS.fetch(request);
    } catch (err) {
      console.error(err);
      return json({ error: "Something went wrong. Please try again." }, 500);
    }
  }
};
