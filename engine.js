/*
 * UCPGATE Browser-Local Engine (Zero Dependencies, Exact Parity with Python 3.11 Core)
 * Evaluates 10 Universal Commerce Protocol (/.well-known/ucp, 2026-01-23), AP2 Mandate,
 * Stateless MCP (2026-07-28), A2A (/.well-known/agent.json), and Schema.org Offer gates,
 * plus 1-Click Manifest + Cloudflare Worker + Nginx Edge Config synthesis.
 */

export const DEFAULT_UCP_VERSION = "2026-01-23";
export const MCP_STATELESS_REVISION = "2026-07-28";

export const ISO_4217_CURRENCIES = new Set([
  "USD", "JPY", "EUR", "GBP", "CAD", "AUD", "NZD", "CHF", "SGD", "HKD",
  "KRW", "TWD", "SEK", "NOK", "DKK", "PLN", "CZK", "BRL", "MXN", "INR",
  "THB", "MYR", "IDR", "PHP", "VND", "ZAR", "AED", "SAR", "ILS", "TRY", "CNY"
]);

export const GATE_DEFINITIONS = [
  {
    gate_number: 1,
    gate_id: "UCP-01",
    weight: 10,
    title: "Envelope & Date-Stamped Protocol Version (ucp.version)",
    spec_ref: "ucp.dev/specification/overview#profile-version"
  },
  {
    gate_number: 2,
    gate_id: "UCP-02",
    weight: 10,
    title: "Reverse-Domain Namespace Syntax & Collision Safety",
    spec_ref: "ucp.dev/specification/overview#namespaces"
  },
  {
    gate_number: 3,
    gate_id: "UCP-03",
    weight: 10,
    title: "Service Transports, HTTPS-Only Endpoints & SSRF Guard",
    spec_ref: "ucp.dev/specification/overview#services"
  },
  {
    gate_number: 4,
    gate_id: "UCP-04",
    weight: 10,
    title: "Core dev.ucp.shopping.checkout Completeness & Schema Alignment",
    spec_ref: "ucp.dev/specification/checkout"
  },
  {
    gate_number: 5,
    gate_id: "UCP-05",
    weight: 10,
    title: "Capability Composition DAG (extends Resolution & Cycle Check)",
    spec_ref: "ucp.dev/specification/overview#capability-extensions"
  },
  {
    gate_number: 6,
    gate_id: "UCP-06",
    weight: 10,
    title: "Payment Handlers (Google Pay / Stripe / Shop Pay) UUID & HTTPS Schemas",
    spec_ref: "ucp.dev/specification/payments"
  },
  {
    gate_number: 7,
    gate_id: "UCP-07",
    weight: 10,
    title: "Stateless MCP (2026-07-28) / OpenAPI & A2A Dual-Surface Parity",
    spec_ref: "ucp.dev/specification/mcp"
  },
  {
    gate_number: 8,
    gate_id: "UCP-08",
    weight: 10,
    title: "Price, Currency & Inventory Hallucination Guard (Schema.org Parity)",
    spec_ref: "schema.org/Offer + ucp.dev/specification/checkout"
  },
  {
    gate_number: 9,
    gate_id: "UCP-09",
    weight: 10,
    title: "AP2 Payment Mandate & Idempotency / Replay Protection",
    spec_ref: "ucp.dev/specification/ap2-mandate"
  },
  {
    gate_number: 10,
    gate_id: "UCP-10",
    weight: 10,
    title: "Edge Discovery Headers (JSON MIME, CORS, Cache) & 1-Click Bundle",
    spec_ref: "rfc8615 + ucp.dev/specification/discovery"
  }
];

const OFFICIAL_UCP_SERVICES = new Set(["dev.ucp.shopping"]);
const OFFICIAL_UCP_CAPABILITIES = new Set([
  "dev.ucp.shopping.checkout",
  "dev.ucp.shopping.fulfillment",
  "dev.ucp.shopping.discount",
  "dev.ucp.shopping.order",
  "dev.ucp.shopping.cart",
  "dev.ucp.shopping.catalog",
  "dev.ucp.shopping.ap2_mandate",
  "dev.ucp.identity_linking"
]);
const CHECKOUT_EXTENSION_CAPABILITIES = [
  "dev.ucp.shopping.fulfillment",
  "dev.ucp.shopping.discount",
  "dev.ucp.shopping.ap2_mandate"
];
const ALLOWED_TRANSPORTS = new Set(["rest", "mcp", "a2a", "embedded"]);

const CANONICAL_CAPABILITY_ALIASES = {
  checkout: "dev.ucp.shopping.checkout",
  "dev.ucp.shopping.checkout": "dev.ucp.shopping.checkout",
  fulfillment: "dev.ucp.shopping.fulfillment",
  "dev.ucp.shopping.fulfillment": "dev.ucp.shopping.fulfillment",
  discount: "dev.ucp.shopping.discount",
  "dev.ucp.shopping.discount": "dev.ucp.shopping.discount",
  order: "dev.ucp.shopping.order",
  "dev.ucp.shopping.order": "dev.ucp.shopping.order",
  ap2_mandate: "dev.ucp.shopping.ap2_mandate",
  "dev.ucp.shopping.ap2_mandate": "dev.ucp.shopping.ap2_mandate",
  identity_linking: "dev.ucp.identity_linking",
  "dev.ucp.identity_linking": "dev.ucp.identity_linking"
};

const DEFAULT_ENABLED_CAPABILITIES = [
  "dev.ucp.shopping.checkout",
  "dev.ucp.shopping.fulfillment",
  "dev.ucp.shopping.discount",
  "dev.ucp.shopping.order",
  "dev.ucp.shopping.ap2_mandate"
];

const DEFAULT_PAYMENT_HANDLERS = ["com.google.pay", "com.stripe.pay"];

const PAYMENT_HANDLER_ALIASES = {
  google_pay: "com.google.pay",
  "com.google.pay": "com.google.pay",
  stripe: "com.stripe.pay",
  "com.stripe.pay": "com.stripe.pay",
  "com.stripe.payments": "com.stripe.payments",
  shop_pay: "shop.pay",
  "shop.pay": "shop.pay",
  "dev.shopify.shop_pay": "dev.shopify.shop_pay"
};

const DOMAIN_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;
const EMBEDDED_DATE_RE = /\b(20\d{2}-\d{2}-\d{2})\b/g;
const SERVICE_NS_RE = /^[a-z]{2,16}(?:\.[a-z0-9_]+){2,}$/;
const CAPABILITY_NS_RE = /^[a-z]{2,16}(?:\.[a-z0-9_]+){3,}$/;
const HANDLER_NS_RE = /^[a-z]{2,16}(?:\.[a-z0-9_]+){2,}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SECRET_LEAK_RE = /\b(?:sk_live_[A-Za-z0-9]{10,}|sk_test_[A-Za-z0-9]{10,}|rk_live_[A-Za-z0-9]{10,}|whsec_[A-Za-z0-9]{10,}|shpat_[A-Za-z0-9]{10,}|shpss_[A-Za-z0-9]{10,}|shpca_[A-Za-z0-9]{10,})\b/;
const JSON_LD_SCRIPT_RE = /<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;

const FORBIDDEN_HOSTS = new Set([
  "localhost",
  "localhost.localdomain",
  "ip6-localhost",
  "ip6-loopback",
  "metadata.google.internal",
  "metadata.goog",
  "metadata"
]);
const FORBIDDEN_HOST_SUFFIXES = [".local", ".internal", ".localhost", ".home.arpa"];
const TEST_TLD_PREFIXES = ["local.", "test.", "invalid.", "localhost.", "internal."];
const VALID_SCHEMA_AVAILABILITIES = new Set([
  "instock",
  "outofstock",
  "preorder",
  "presale",
  "limitedavailability",
  "onlineonly",
  "instoreonly",
  "backorder",
  "soldout",
  "discontinued"
]);

// RFC 4122 NAMESPACE_URL bytes: 6ba7b811-9dad-11d1-80b4-00c04fd430c8
const NAMESPACE_URL_BYTES = new Uint8Array([
  0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1,
  0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8
]);
const HEX_CHARS = "0123456789abcdef";

function byteToHex(b) {
  return HEX_CHARS[(b >> 4) & 15] + HEX_CHARS[b & 15];
}

function sha1Bytes(msgBytes) {
  const ml = msgBytes.length;
  const bitLenHi = Math.floor((ml * 8) / 0x100000000);
  const bitLenLo = (ml * 8) >>> 0;
  const padLen = ((ml + 9 + 63) >> 6) << 6;
  const buf = new Uint8Array(padLen);
  buf.set(msgBytes, 0);
  buf[ml] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(padLen - 8, bitLenHi, false);
  dv.setUint32(padLen - 4, bitLenLo, false);

  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;
  const w = new Uint32Array(80);

  for (let off = 0; off < padLen; off += 64) {
    for (let i = 0; i < 16; i += 1) {
      w[i] = dv.getUint32(off + i * 4, false);
    }
    for (let i = 16; i < 80; i += 1) {
      const x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
      w[i] = ((x << 1) | (x >>> 31)) >>> 0;
    }
    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;

    for (let i = 0; i < 80; i += 1) {
      let f = 0;
      let k = 0;
      if (i < 20) {
        f = ((b & c) | (~b & d)) >>> 0;
        k = 0x5a827999;
      } else if (i < 40) {
        f = (b ^ c ^ d) >>> 0;
        k = 0x6ed9eba1;
      } else if (i < 60) {
        f = ((b & c) | (b & d) | (c & d)) >>> 0;
        k = 0x8f1bbcdc;
      } else {
        f = (b ^ c ^ d) >>> 0;
        k = 0xca62c1d6;
      }
      const rotA = ((a << 5) | (a >>> 27)) >>> 0;
      const temp = (rotA + f + e + k + w[i]) >>> 0;
      e = d;
      d = c;
      c = ((b << 30) | (b >>> 2)) >>> 0;
      b = a;
      a = temp;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
  }

  const out = new Uint8Array(20);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, h0, false);
  outView.setUint32(4, h1, false);
  outView.setUint32(8, h2, false);
  outView.setUint32(12, h3, false);
  outView.setUint32(16, h4, false);
  return out;
}

export function deterministicHandlerUuid(domain, handlerKey, version = DEFAULT_UCP_VERSION) {
  const normDomain = String(domain || "").trim().toLowerCase().replace(/\.+$/, "");
  const normHandler = String(handlerKey || "").trim().toLowerCase();
  const normVersion = String(version || DEFAULT_UCP_VERSION).trim();
  const seedUri = `https://${normDomain}/.well-known/ucp?version=${normVersion}#${normHandler}`;
  const nameBytes = new TextEncoder().encode(seedUri);
  const combined = new Uint8Array(NAMESPACE_URL_BYTES.length + nameBytes.length);
  combined.set(NAMESPACE_URL_BYTES, 0);
  combined.set(nameBytes, NAMESPACE_URL_BYTES.length);

  const digest = sha1Bytes(combined);
  const b = digest.slice(0, 16);
  b[6] = (b[6] & 0x0f) | 0x50;
  b[8] = (b[8] & 0x3f) | 0x80;

  return (
    byteToHex(b[0]) + byteToHex(b[1]) + byteToHex(b[2]) + byteToHex(b[3]) + "-" +
    byteToHex(b[4]) + byteToHex(b[5]) + "-" +
    byteToHex(b[6]) + byteToHex(b[7]) + "-" +
    byteToHex(b[8]) + byteToHex(b[9]) + "-" +
    byteToHex(b[10]) + byteToHex(b[11]) + byteToHex(b[12]) +
    byteToHex(b[13]) + byteToHex(b[14]) + byteToHex(b[15])
  );
}

export class UcpParseError extends Error {
  constructor(message) {
    super(message);
    this.name = "UcpParseError";
  }
}

export function stripJsoncComments(rawText) {
  let out = "";
  let i = 0;
  const n = rawText.length;
  let inStr = false;
  let escaped = false;

  while (i < n) {
    const ch = rawText[i];
    if (inStr) {
      out += ch;
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === "\"") {
        inStr = false;
      }
      i += 1;
      continue;
    }

    if (ch === "\"") {
      inStr = true;
      out += ch;
      i += 1;
      continue;
    }

    if (ch === "/" && i + 1 < n && rawText[i + 1] === "/") {
      i += 2;
      while (i < n && rawText[i] !== "\n" && rawText[i] !== "\r") {
        i += 1;
      }
      continue;
    }

    if (ch === "/" && i + 1 < n && rawText[i + 1] === "*") {
      i += 2;
      while (i + 1 < n && !(rawText[i] === "*" && rawText[i + 1] === "/")) {
        if (rawText[i] === "\n" || rawText[i] === "\r") {
          out += rawText[i];
        }
        i += 1;
      }
      i += 2;
      continue;
    }

    out += ch;
    i += 1;
  }

  return out;
}

function parseIpv4Octets(str) {
  const parts = str.split(".");
  if (parts.length !== 4) return null;
  const octets = [];
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    if (p.length > 1 && p.startsWith("0")) return null;
    const n = Number(p);
    if (n < 0 || n > 255) return null;
    octets.push(n);
  }
  return octets;
}

function isIpv4Blocked(o) {
  const [a, b, c] = o;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return true;
  if (a === 198 && (b === 18 || b === 19)) return true; // Benchmarking
  if (a === 198 && b === 51 && c === 100) return true;
  if (a === 203 && b === 0 && c === 113) return true;
  if (a >= 224) return true; // Multicast & Reserved
  return false;
}

function inspectIpLiteral(host) {
  let clean = host.trim().toLowerCase();
  if (clean.startsWith("[") && clean.endsWith("]")) {
    clean = clean.slice(1, -1);
  }
  if (clean.includes("%")) {
    clean = clean.split("%", 1)[0];
  }

  const v4 = parseIpv4Octets(clean);
  if (v4) {
    return { isIp: true, blocked: isIpv4Blocked(v4) };
  }

  if (clean.includes(":")) {
    if (clean === "::" || clean === "::1") {
      return { isIp: true, blocked: true };
    }
    if (clean.startsWith("::ffff:")) {
      const tail = clean.slice(7);
      const mappedV4 = parseIpv4Octets(tail);
      if (mappedV4) {
        return { isIp: true, blocked: isIpv4Blocked(mappedV4) };
      }
      const hexMatch = tail.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
      if (hexMatch) {
        const hi = parseInt(hexMatch[1], 16);
        const lo = parseInt(hexMatch[2], 16);
        return { isIp: true, blocked: isIpv4Blocked([(hi >> 8) & 255, hi & 255, (lo >> 8) & 255, lo & 255]) };
      }
    }
    const firstGroup = clean.split(":")[0];
    if (firstGroup) {
      const fg = parseInt(firstGroup, 16);
      if (!Number.isNaN(fg)) {
        if ((fg & 0xfe00) === 0xfc00) return { isIp: true, blocked: true }; // fc00::/7 ULA
        if ((fg & 0xffc0) === 0xfe80) return { isIp: true, blocked: true }; // fe80::/10 Link-local
        if ((fg & 0xff00) === 0xff00) return { isIp: true, blocked: true }; // ff00::/8 Multicast
        if (fg === 0x2001 && clean.startsWith("2001:db8:")) return { isIp: true, blocked: true };
        if ((fg & 0xe000) !== 0x2000) return { isIp: true, blocked: true }; // Non-global unicast
      }
    }
    return { isIp: true, blocked: false };
  }

  return { isIp: false, blocked: false };
}

export function normalizeStoreDomain(rawDomain) {
  const raw = String(rawDomain || "").trim();
  if (!raw) {
    throw new Error("Store domain is required.");
  }

  let host = "";
  if (raw.includes("://")) {
    let parsed;
    try {
      parsed = new URL(raw);
    } catch {
      throw new Error(`Could not extract hostname from ${rawDomain}.`);
    }
    host = (parsed.hostname || "").trim().toLowerCase().replace(/\.+$/, "");
  } else {
    host = raw.split("/")[0].split("?")[0].split("#")[0].trim().toLowerCase().replace(/\.+$/, "");
    if (host.includes(":")) {
      host = host.split(":")[0];
    }
  }

  if (!host) {
    throw new Error(`Could not extract hostname from ${rawDomain}.`);
  }

  if (FORBIDDEN_HOSTS.has(host) || FORBIDDEN_HOST_SUFFIXES.some((sfx) => host.endsWith(sfx))) {
    throw new Error(`Reserved or local hostname is disallowed for UCP merchant discovery: ${host}`);
  }

  const ipCheck = inspectIpLiteral(host);
  if (ipCheck.isIp) {
    throw new Error(`IP literal ${host} is disallowed; provide a public DNS domain.`);
  }

  const labels = host.split(".");
  const tld = labels[labels.length - 1] || "";
  if (labels.length < 2 || tld.length < 2 || !/^[a-z]+$/.test(tld)) {
    throw new Error(`Invalid public store domain syntax: ${host}`);
  }
  for (const label of labels) {
    if (!DOMAIN_LABEL_RE.test(label)) {
      throw new Error(`Invalid DNS label '${label}' in domain ${host}.`);
    }
  }

  return host;
}

export function normalizePlatform(rawPlatform) {
  const val = String(rawPlatform || "shopify").trim().toLowerCase().replace(/[-\s]+/g, "_");
  if (val === "shopify" || val === "shopify_plus") return "shopify";
  if (val === "custom_rest" || val === "rest" || val === "openapi" || val === "custom") return "custom_rest";
  if (val === "stateless_mcp" || val === "mcp" || val === "mcp_streamable_http") return "stateless_mcp";
  throw new Error(`Unsupported platform '${rawPlatform}'; expected 'Shopify', 'Custom REST', or 'Stateless MCP'.`);
}

function humanStoreTitle(domain, storeName = null) {
  if (storeName && String(storeName).trim()) {
    return String(storeName).trim();
  }
  const stem = domain.split(".")[0] || domain;
  const words = stem
    .split(/[-_]+/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1));
  return words.length ? words.join(" ") : domain;
}

function normalizeCapabilitiesList(capabilities) {
  const rawItems = Array.isArray(capabilities) ? capabilities : DEFAULT_ENABLED_CAPABILITIES;
  const resolved = [];
  for (const item of rawItems) {
    const key = String(item || "").trim().toLowerCase();
    if (!key) continue;
    const mapped = CANONICAL_CAPABILITY_ALIASES[key] || key;
    if (!resolved.includes(mapped)) {
      resolved.push(mapped);
    }
  }

  const needsCheckout =
    resolved.length === 0 ||
    resolved.includes("dev.ucp.shopping.fulfillment") ||
    resolved.includes("dev.ucp.shopping.discount") ||
    resolved.includes("dev.ucp.shopping.ap2_mandate");

  if (needsCheckout && !resolved.includes("dev.ucp.shopping.checkout")) {
    resolved.unshift("dev.ucp.shopping.checkout");
  } else if (resolved.includes("dev.ucp.shopping.checkout")) {
    const idx = resolved.indexOf("dev.ucp.shopping.checkout");
    resolved.splice(idx, 1);
    resolved.unshift("dev.ucp.shopping.checkout");
  }
  return resolved;
}

function normalizePaymentHandlersList(handlers) {
  const rawItems = Array.isArray(handlers) ? handlers : DEFAULT_PAYMENT_HANDLERS;
  const resolved = [];
  for (const item of rawItems) {
    const key = String(item || "").trim().toLowerCase();
    if (!key) continue;
    const mapped = PAYMENT_HANDLER_ALIASES[key] || key;
    if (!resolved.includes(mapped)) {
      resolved.push(mapped);
    }
  }
  if (resolved.length === 0) {
    resolved.push("com.google.pay");
  }
  return resolved;
}

function normalizeCurrenciesList(currencies) {
  const rawItems = Array.isArray(currencies) ? currencies : ["USD"];
  const resolved = [];
  for (const item of rawItems) {
    const code = String(item || "").trim().toUpperCase();
    if (!code) continue;
    if (!ISO_4217_CURRENCIES.has(code)) {
      throw new Error(`Unsupported or non-ISO-4217 currency code: '${code}'`);
    }
    if (!resolved.includes(code)) {
      resolved.push(code);
    }
  }
  return resolved.length ? resolved : ["USD"];
}

function buildPaymentHandlerEntry(domain, handlerKey, version) {
  const handlerId = deterministicHandlerUuid(domain, handlerKey, version);
  if (handlerKey === "com.google.pay") {
    return {
      id: handlerId,
      version,
      spec: `https://pay.google.com/gp/p/ucp/${version}/`,
      schema: `https://pay.google.com/gp/p/ucp/${version}/schemas/config.json`,
      config_schema: `https://pay.google.com/gp/p/ucp/${version}/schemas/config.json`,
      instrument_schemas: [
        `https://pay.google.com/gp/p/ucp/${version}/schemas/card_payment_instrument.json`
      ],
      config: {
        environment: "PRODUCTION",
        ap2_mandate_verification: true
      }
    };
  }
  if (handlerKey === "com.stripe.pay" || handlerKey === "com.stripe.payments") {
    return {
      id: handlerId,
      version,
      spec: `https://docs.stripe.com/agentic-commerce/ucp/${version}`,
      schema: `https://ucp.stripe.com/${version}/schemas/config.json`,
      config_schema: `https://ucp.stripe.com/${version}/schemas/config.json`,
      instrument_schemas: [
        `https://ucp.stripe.com/${version}/schemas/shared_payment_token.json`
      ],
      config: {
        network_tokenization: true,
        ap2_mandate_verification: true
      }
    };
  }
  if (handlerKey === "shop.pay" || handlerKey === "dev.shopify.shop_pay") {
    return {
      id: handlerId,
      version,
      spec: "https://shopify.dev/docs/agents/ucp/shop-pay",
      schema: `https://shopify.dev/ucp/${version}/schemas/shop_pay_config.json`,
      config_schema: `https://shopify.dev/ucp/${version}/schemas/shop_pay_config.json`,
      instrument_schemas: [
        `https://shopify.dev/ucp/${version}/schemas/shop_pay_instrument.json`
      ],
      config: {
        express_wallet: true,
        ap2_mandate_verification: true
      }
    };
  }
  return {
    id: handlerId,
    version,
    spec: `https://${domain}/ucp/specs/payments/${handlerKey}`,
    schema: `https://${domain}/ucp/${version}/schemas/payments/${handlerKey}.json`,
    config_schema: `https://${domain}/ucp/${version}/schemas/payments/${handlerKey}.json`,
    instrument_schemas: [
      `https://${domain}/ucp/${version}/schemas/payments/${handlerKey}_instrument.json`
    ],
    config: {
      ap2_mandate_verification: true
    }
  };
}

function buildServicesBlock(domain, platform, version) {
  if (platform === "shopify") {
    return {
      "dev.ucp.shopping": [
        {
          version,
          spec: "https://ucp.dev/specification/overview",
          transport: "rest",
          endpoint: `https://${domain}/api/ucp/${version}`,
          schema: `https://ucp.dev/${version}/services/shopping/openapi.json`
        },
        {
          version,
          spec: "https://ucp.dev/specification/mcp",
          transport: "mcp",
          endpoint: `https://${domain}/api/ucp/mcp`,
          schema: `https://ucp.dev/${version}/services/shopping/openrpc.json`,
          config: {
            mcp_protocol_version: MCP_STATELESS_REVISION,
            stateless_streamable_http: true,
            required_meta: ["ucp-agent", "idempotency-key"]
          }
        }
      ]
    };
  }
  if (platform === "stateless_mcp") {
    return {
      "dev.ucp.shopping": [
        {
          version,
          spec: "https://ucp.dev/specification/mcp",
          transport: "mcp",
          endpoint: `https://${domain}/ucp/mcp`,
          schema: `https://ucp.dev/${version}/services/shopping/openrpc.json`,
          config: {
            mcp_protocol_version: MCP_STATELESS_REVISION,
            stateless_streamable_http: true,
            required_meta: ["ucp-agent", "idempotency-key"]
          }
        },
        {
          version,
          spec: "https://ucp.dev/specification/overview",
          transport: "rest",
          endpoint: `https://${domain}/ucp/v1`,
          schema: `https://ucp.dev/${version}/services/shopping/openapi.json`
        }
      ]
    };
  }
  return {
    "dev.ucp.shopping": [
      {
        version,
        spec: "https://ucp.dev/specification/overview",
        transport: "rest",
        endpoint: `https://${domain}/ucp/v1`,
        schema: `https://ucp.dev/${version}/services/shopping/openapi.json`
      }
    ]
  };
}

function buildCapabilitiesBlock(domain, capabilityKeys, currencies, version) {
  const caps = {};
  for (const key of capabilityKeys) {
    if (key === "dev.ucp.shopping.checkout") {
      caps[key] = [
        {
          version,
          spec: "https://ucp.dev/specification/checkout",
          schema: `https://ucp.dev/${version}/schemas/shopping/checkout.json`,
          config: {
            supported_currencies: [...currencies],
            seller_of_record: domain,
            idempotency_key_required: true,
            idempotency_ttl_seconds: 86400,
            ap2_mandate_required: true
          }
        }
      ];
    } else if (key === "dev.ucp.shopping.fulfillment") {
      caps[key] = [
        {
          version,
          spec: "https://ucp.dev/specification/fulfillment",
          schema: `https://ucp.dev/${version}/schemas/shopping/fulfillment.json`,
          extends: "dev.ucp.shopping.checkout"
        }
      ];
    } else if (key === "dev.ucp.shopping.discount") {
      caps[key] = [
        {
          version,
          spec: "https://ucp.dev/specification/discount",
          schema: `https://ucp.dev/${version}/schemas/shopping/discount.json`,
          extends: "dev.ucp.shopping.checkout"
        }
      ];
    } else if (key === "dev.ucp.shopping.order") {
      caps[key] = [
        {
          version,
          spec: "https://ucp.dev/specification/order",
          schema: `https://ucp.dev/${version}/schemas/shopping/order.json`
        }
      ];
    } else if (key === "dev.ucp.shopping.ap2_mandate") {
      caps[key] = [
        {
          version,
          spec: "https://ucp.dev/specification/ap2-mandate",
          schema: `https://ucp.dev/${version}/schemas/shopping/ap2_mandate.json`,
          extends: "dev.ucp.shopping.checkout",
          config: {
            mandate_formats: ["CheckoutMandate", "SD-JWT-VC"],
            require_user_signature: true,
            replay_nonce_ttl_seconds: 300
          }
        }
      ];
    } else if (key === "dev.ucp.identity_linking") {
      caps[key] = [
        {
          version,
          spec: "https://ucp.dev/specification/identity-linking",
          schema: `https://ucp.dev/${version}/schemas/identity_linking.json`
        }
      ];
    } else {
      const parts = key.split(".");
      const slug = parts[parts.length - 1];
      const entry = {
        version,
        spec: `https://${domain}/ucp/specs/${slug}`,
        schema: `https://${domain}/ucp/${version}/schemas/${slug}.json`
      };
      if (capabilityKeys.includes("dev.ucp.shopping.checkout")) {
        entry.extends = "dev.ucp.shopping.checkout";
      }
      caps[key] = [entry];
    }
  }
  return caps;
}

export function buildA2aAgentCard(domain, options = {}) {
  const platform = options.platform || "shopify";
  const caps = options.capabilityKeys || DEFAULT_ENABLED_CAPABILITIES;
  const version = options.version || DEFAULT_UCP_VERSION;
  const title = humanStoreTitle(domain, options.storeName || null);
  const endpointPath = platform === "shopify" ? "/api/ucp/a2a" : "/ucp/a2a";

  const skills = [
    {
      id: "ucp-shopping-checkout",
      name: `${title} UCP Native Checkout`,
      description: "Negotiates cart pricing, taxes, and AP2 payment mandates via Universal Commerce Protocol.",
      tags: ["commerce", "ucp", "checkout", "ap2"]
    }
  ];
  if (caps.includes("dev.ucp.shopping.fulfillment")) {
    skills.push({
      id: "ucp-shopping-fulfillment",
      name: "Fulfillment & Shipping Options",
      description: "Calculates real-time carrier rates, delivery windows, and pickup availability.",
      tags: ["commerce", "ucp", "fulfillment"]
    });
  }
  if (caps.includes("dev.ucp.shopping.order")) {
    skills.push({
      id: "ucp-shopping-order",
      name: "Post-Purchase Order Lifecycle",
      description: "Queries verified order shipment tracking, receipts, and return eligibility.",
      tags: ["commerce", "ucp", "orders"]
    });
  }

  return {
    name: `${title} Commerce Agent`,
    description: `Official UCP (${version}) and AP2 mandate-verified commerce endpoint for ${domain}.`,
    url: `https://${domain}${endpointPath}`,
    version: "1.0.0",
    protocolVersion: "0.3.0",
    capabilities: {
      streaming: false,
      pushNotifications: false,
      stateTransitionHistory: true
    },
    defaultInputModes: ["application/json"],
    defaultOutputModes: ["application/json"],
    skills
  };
}

export function buildCloudflareWorkerSnippet(manifest, agentCard = null) {
  const manifestJson = JSON.stringify(manifest, null, 2);
  const agentJson = agentCard !== null ? JSON.stringify(agentCard, null, 2) : "null";
  const lines = [
    "// Cloudflare Worker Edge Route: https://<your-domain>/.well-known/*",
    "const UCP_MANIFEST = " + manifestJson + ";",
    "const A2A_AGENT_CARD = " + agentJson + ";",
    "",
    "const EDGE_HEADERS = {",
    "  \"Content-Type\": \"application/json; charset=utf-8\",",
    "  \"Access-Control-Allow-Origin\": \"*\",",
    "  \"Access-Control-Allow-Methods\": \"GET, HEAD, OPTIONS\",",
    "  \"Access-Control-Allow-Headers\": \"Content-Type, Accept, Idempotency-Key, UCP-Agent\",",
    "  \"Access-Control-Expose-Headers\": \"Content-Type, Cache-Control, ETag\",",
    "  \"Cache-Control\": \"public, max-age=3600, stale-while-revalidate=86400\",",
    "  \"X-Content-Type-Options\": \"nosniff\",",
    "};",
    "",
    "export default {",
    "  async fetch(request) {",
    "    const url = new URL(request.url);",
    "    if (request.method === \"OPTIONS\") {",
    "      return new Response(null, { status: 204, headers: EDGE_HEADERS });",
    "    }",
    "    if (request.method !== \"GET\" && request.method !== \"HEAD\") {",
    "      return new Response(JSON.stringify({ error: \"method_not_allowed\" }), {",
    "        status: 405,",
    "        headers: EDGE_HEADERS,",
    "      });",
    "    }",
    "    if (url.pathname === \"/.well-known/ucp\") {",
    "      const body = JSON.stringify(UCP_MANIFEST, null, 2);",
    "      return new Response(request.method === \"HEAD\" ? null : body, {",
    "        status: 200,",
    "        headers: EDGE_HEADERS,",
    "      });",
    "    }",
    "    if (A2A_AGENT_CARD && (url.pathname === \"/.well-known/agent.json\" || url.pathname === \"/.well-known/agent-card.json\")) {",
    "      const body = JSON.stringify(A2A_AGENT_CARD, null, 2);",
    "      return new Response(request.method === \"HEAD\" ? null : body, {",
    "        status: 200,",
    "        headers: EDGE_HEADERS,",
    "      });",
    "    }",
    "    return new Response(JSON.stringify({ error: \"not_found\" }), { status: 404, headers: EDGE_HEADERS });",
    "  },",
    "};"
  ];
  return lines.join("\n") + "\n";
}

export function buildNginxSnippet(domain) {
  const lines = [
    `# Nginx TLS edge configuration for ${domain}`,
    "location = /.well-known/ucp {",
    "    default_type application/json;",
    "    charset utf-8;",
    "    add_header Access-Control-Allow-Origin \"*\" always;",
    "    add_header Access-Control-Allow-Methods \"GET, HEAD, OPTIONS\" always;",
    "    add_header Access-Control-Allow-Headers \"Content-Type, Accept, Idempotency-Key, UCP-Agent\" always;",
    "    add_header Access-Control-Expose-Headers \"Content-Type, Cache-Control, ETag\" always;",
    "    add_header Cache-Control \"public, max-age=3600, stale-while-revalidate=86400\" always;",
    "    add_header X-Content-Type-Options \"nosniff\" always;",
    "    if ($request_method = OPTIONS) {",
    "        return 204;",
    "    }",
    "    try_files /.well-known/ucp.json =404;",
    "}",
    "",
    "location = /.well-known/agent.json {",
    "    default_type application/json;",
    "    charset utf-8;",
    "    add_header Access-Control-Allow-Origin \"*\" always;",
    "    add_header Cache-Control \"public, max-age=3600, stale-while-revalidate=86400\" always;",
    "    add_header X-Content-Type-Options \"nosniff\" always;",
    "    try_files /.well-known/agent.json =404;",
    "}"
  ];
  return lines.join("\n") + "\n";
}

export function generateUcpBundle(domain, options = {}) {
  const normDomain = normalizeStoreDomain(domain);
  const normPlatform = normalizePlatform(options.platform || "shopify");
  const normVersion = String(options.version || DEFAULT_UCP_VERSION).trim();
  if (!DATE_RE.test(normVersion)) {
    throw new Error(`UCP version must match YYYY-MM-DD (got '${options.version}').`);
  }

  const capKeys = normalizeCapabilitiesList(options.capabilities || null);
  const handlerKeys = normalizePaymentHandlersList(options.paymentHandlers || options.payment_handlers || null);
  const normCurrencies = normalizeCurrenciesList(options.currencies || null);
  const includeA2a = options.includeA2aAgentCard !== false && options.include_a2a_agent_card !== false;
  const storeName = options.storeName || options.store_name || null;

  const servicesBlock = buildServicesBlock(normDomain, normPlatform, normVersion);
  const capabilitiesBlock = buildCapabilitiesBlock(normDomain, capKeys, normCurrencies, normVersion);
  const handlersBlock = {};
  for (const hKey of handlerKeys) {
    handlersBlock[hKey] = [buildPaymentHandlerEntry(normDomain, hKey, normVersion)];
  }

  const manifest = {
    ucp: {
      version: normVersion,
      services: servicesBlock,
      capabilities: capabilitiesBlock,
      payment_handlers: handlersBlock
    }
  };

  const agentCard = includeA2a
    ? buildA2aAgentCard(normDomain, {
        platform: normPlatform,
        capabilityKeys: capKeys,
        version: normVersion,
        storeName
      })
    : null;

  const httpHeaders = {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
    "Access-Control-Expose-Headers": "Content-Type, Cache-Control, ETag",
    "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400",
    "X-Content-Type-Options": "nosniff"
  };

  const primaryCurrency = normCurrencies[0];
  const defaultPrice = primaryCurrency === "JPY" ? "4800" : "34.00";
  const title = humanStoreTitle(normDomain, storeName);
  const schemaOrgProductJsonld = {
    "@context": "https://schema.org",
    "@type": "Product",
    name: `${title} Flagship SKU`,
    sku: "UCP-SKU-101",
    offers: {
      "@type": "Offer",
      url: `https://${normDomain}/products/ucp-sku-101`,
      priceCurrency: primaryCurrency,
      price: defaultPrice,
      availability: "https://schema.org/InStock",
      seller: {
        "@type": "Organization",
        name: title
      }
    }
  };

  return {
    domain: normDomain,
    platform: normPlatform,
    version: normVersion,
    enabled_capabilities: capKeys,
    enabled_payment_handlers: handlerKeys,
    supported_currencies: normCurrencies,
    manifest,
    agent_card: agentCard,
    http_headers: httpHeaders,
    schema_org_product_jsonld: schemaOrgProductJsonld,
    cloudflare_worker_js: buildCloudflareWorkerSnippet(manifest, agentCard),
    nginx_conf: buildNginxSnippet(normDomain)
  };
}

function isValidCalendarDate(val) {
  if (typeof val !== "string") return { ok: false, clean: null };
  const s = val.trim();
  const m = s.match(DATE_RE);
  if (!m) return { ok: false, clean: null };
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  if (month < 1 || month > 12 || day < 1 || day > 31) return { ok: false, clean: null };
  const dtObj = new Date(Date.UTC(year, month - 1, day));
  if (
    dtObj.getUTCFullYear() !== year ||
    dtObj.getUTCMonth() + 1 !== month ||
    dtObj.getUTCDate() !== day
  ) {
    return { ok: false, clean: null };
  }
  return { ok: true, clean: s };
}

export function inspectHttpsPublicUrl(rawUrl) {
  if (typeof rawUrl !== "string" || !rawUrl.trim()) {
    return { ok: false, reason: "MISSING_URL", detail: "URL is missing or empty.", host: "" };
  }
  const s = rawUrl.trim();
  let parsed;
  try {
    parsed = new URL(s);
  } catch {
    return { ok: false, reason: "INVALID_URI_SCHEME", detail: `Malformed URL: ${s}`, host: "" };
  }

  const scheme = (parsed.protocol || "").replace(/:$/, "").toLowerCase();
  const host = (parsed.hostname || "").trim().toLowerCase().replace(/\.+$/, "");

  if (scheme !== "https" && scheme !== "http") {
    return {
      ok: false,
      reason: "INVALID_URI_SCHEME",
      detail: `Only https:// URLs are permitted (got ${scheme || "none"}): ${s}`,
      host: ""
    };
  }
  if (parsed.username || parsed.password) {
    return {
      ok: false,
      reason: "EMBEDDED_CREDENTIALS",
      detail: "Embedded URL userinfo credentials are disallowed.",
      host
    };
  }
  if (!host) {
    return { ok: false, reason: "MISSING_HOSTNAME", detail: `Missing hostname in URL: ${s}`, host: "" };
  }
  if (FORBIDDEN_HOSTS.has(host) || FORBIDDEN_HOST_SUFFIXES.some((sfx) => host.endsWith(sfx))) {
    return {
      ok: false,
      reason: "SSRF_RESERVED_HOST",
      detail: `Reserved/internal hostname blocked (SSRF risk): ${host}`,
      host
    };
  }

  const ipCheck = inspectIpLiteral(host);
  if (ipCheck.isIp && ipCheck.blocked) {
    return {
      ok: false,
      reason: "SSRF_PRIVATE_IP",
      detail: `Private, loopback, link-local, or reserved IP literal blocked (SSRF risk): ${host}`,
      host
    };
  }

  if (scheme === "http") {
    return {
      ok: false,
      reason: "CLEARTEXT_HTTP_URL",
      detail: `Cleartext HTTP URL disallowed in UCP: ${s}`,
      host
    };
  }

  const tld = host.split(".").pop() || "";
  if (!ipCheck.isIp && (!host.includes(".") || tld.length < 2)) {
    return {
      ok: false,
      reason: "INVALID_PUBLIC_HOST",
      detail: `Hostname is not a valid public DNS domain: ${host}`,
      host
    };
  }

  return {
    ok: true,
    reason: "OK",
    detail: "",
    host,
    path: parsed.pathname || "/",
    has_fragment: Boolean(parsed.hash && parsed.hash.length > 0),
    has_query: Boolean(parsed.search && parsed.search.length > 0)
  };
}

export function extractSchemaOrgOffersFromHtml(html) {
  if (typeof html !== "string" || !html.trim()) return [];
  const offers = [];

  function visit(node, parentName = "", parentSku = "") {
    if (Array.isArray(node)) {
      for (const child of node) visit(child, parentName, parentSku);
      return;
    }
    if (!node || typeof node !== "object") return;

    if (Array.isArray(node["@graph"])) {
      visit(node["@graph"], parentName, parentSku);
    }

    const rawType = node["@type"];
    const typeList = Array.isArray(rawType) ? rawType.map(String) : (rawType ? [String(rawType)] : []);
    const normTypes = new Set(typeList.map((t) => t.split("/").pop().toLowerCase()));

    const curName = String(node.name || parentName || "").trim();
    const curSku = String(node.sku || parentSku || "").trim();

    if (normTypes.has("product") && "offers" in node) {
      visit(node.offers, curName, curSku);
      return;
    }

    if (normTypes.has("offer") || normTypes.has("aggregateoffer")) {
      const rawPrice = node.price !== undefined && node.price !== null ? node.price : (node.lowPrice ?? null);
      offers.push({
        name: curName || "Unnamed Product",
        sku: curSku,
        price: rawPrice,
        price_currency: String(node.priceCurrency || "").trim(),
        availability: String(node.availability || "").trim()
      });
      if ("offers" in node) {
        visit(node.offers, curName, curSku);
      }
    }
  }

  JSON_LD_SCRIPT_RE.lastIndex = 0;
  let match;
  while ((match = JSON_LD_SCRIPT_RE.exec(html)) !== null) {
    const rawBlock = (match[1] || "").trim();
    if (!rawBlock) continue;
    try {
      visit(JSON.parse(rawBlock));
    } catch {
      // Ignore non-JSON script blocks
    }
  }

  return offers;
}

export function inspectCapabilityDag(capabilities) {
  if (!capabilities || typeof capabilities !== "object" || Array.isArray(capabilities)) {
    return {
      nodes: [],
      edges: [],
      dangling_parents: [],
      cycles: [],
      invalid_extends: [],
      missing_checkout_inheritance: [],
      is_acyclic: true,
      topological_order: []
    };
  }

  const nodes = Object.keys(capabilities);
  const nodeSet = new Set(nodes);
  const parentsMap = {};
  for (const k of nodes) parentsMap[k] = [];
  const edges = [];
  const danglingParents = [];
  const invalidExtends = [];
  const cycles = [];

  for (const [capKey, descriptors] of Object.entries(capabilities)) {
    if (!Array.isArray(descriptors)) continue;
    for (const desc of descriptors) {
      if (!desc || typeof desc !== "object" || Array.isArray(desc) || desc.extends === undefined || desc.extends === null) {
        continue;
      }
      const extVal = desc.extends;
      const parentList = [];
      if (typeof extVal === "string") {
        if (!extVal.trim()) {
          invalidExtends.push({ capability: capKey, detail: "Empty extends string." });
        } else {
          parentList.push(extVal.trim());
        }
      } else if (Array.isArray(extVal)) {
        if (extVal.length === 0 || !extVal.every((x) => typeof x === "string" && x.trim().length > 0)) {
          invalidExtends.push({ capability: capKey, detail: "extends array must contain non-empty strings." });
        } else {
          for (const x of extVal) parentList.push(x.trim());
        }
      } else {
        invalidExtends.push({ capability: capKey, detail: "extends must be a capability string or string array." });
      }

      for (const parent of parentList) {
        edges.push({ from: capKey, to: parent });
        if (parent === capKey) {
          cycles.push([capKey, capKey]);
        } else if (!nodeSet.has(parent)) {
          danglingParents.push({ capability: capKey, missing_parent: parent });
        } else if (!parentsMap[capKey].includes(parent)) {
          parentsMap[capKey].push(parent);
        }
      }
    }
  }

  const color = {};
  for (const k of nodes) color[k] = 0;
  const stack = [];
  const recordedCycleKeys = new Set();
  const topoOrder = [];

  function dfs(node) {
    color[node] = 1;
    stack.push(node);
    for (const parent of parentsMap[node]) {
      if (color[parent] === 0) {
        dfs(parent);
      } else if (color[parent] === 1) {
        const idx = stack.indexOf(parent);
        const cyc = stack.slice(idx).concat([parent]);
        const ring = cyc.slice(0, -1);
        let minPos = 0;
        for (let i = 1; i < ring.length; i += 1) {
          if (ring[i] < ring[minPos]) minPos = i;
        }
        const canon = ring.slice(minPos).concat(ring.slice(0, minPos)).join("->");
        if (!recordedCycleKeys.has(canon)) {
          recordedCycleKeys.add(canon);
          cycles.push(cyc);
        }
      }
    }
    stack.pop();
    color[node] = 2;
    topoOrder.push(node);
  }

  for (const node of nodes) {
    if (color[node] === 0) dfs(node);
  }

  const isAcyclic = cycles.length === 0;
  const missingCheckoutInheritance = [];
  if (isAcyclic) {
    for (const extCap of CHECKOUT_EXTENSION_CAPABILITIES) {
      if (!nodeSet.has(extCap)) continue;
      const visited = new Set();
      const queue = [...(parentsMap[extCap] || [])];
      let reachesCheckout = false;
      while (queue.length > 0) {
        const cur = queue.shift();
        if (cur === "dev.ucp.shopping.checkout") {
          reachesCheckout = true;
          break;
        }
        if (!visited.has(cur)) {
          visited.add(cur);
          queue.push(...(parentsMap[cur] || []));
        }
      }
      if (!reachesCheckout) {
        missingCheckoutInheritance.push(extCap);
      }
    }
  }
  missingCheckoutInheritance.sort();

  return {
    nodes,
    edges,
    dangling_parents: danglingParents,
    cycles,
    invalid_extends: invalidExtends,
    missing_checkout_inheritance: missingCheckoutInheritance,
    is_acyclic: isAcyclic,
    topological_order: isAcyclic ? topoOrder : []
  };
}

function makeGateResult(gateIndex, status, summary, findings) {
  const gdef = GATE_DEFINITIONS[gateIndex];
  const weight = gdef.weight;
  const earned = status === "pass" ? weight : (status === "warn" ? Math.floor(weight / 2) : 0);
  return {
    gate_number: gdef.gate_number,
    gate_id: gdef.gate_id,
    title: gdef.title,
    spec_ref: gdef.spec_ref,
    weight,
    earned_points: earned,
    status,
    summary,
    findings
  };
}

function isPlainObject(v) {
  return Boolean(v && typeof v === "object" && !Array.isArray(v));
}

function inferStoreDomain(bundle, ucpObj) {
  if (typeof bundle.domain === "string" && bundle.domain.trim()) {
    try {
      return normalizeStoreDomain(bundle.domain);
    } catch {
      // fall through
    }
  }
  if (isPlainObject(ucpObj) && isPlainObject(ucpObj.services)) {
    for (const bindings of Object.values(ucpObj.services)) {
      if (Array.isArray(bindings)) {
        for (const b of bindings) {
          if (isPlainObject(b) && typeof b.endpoint === "string") {
            const info = inspectHttpsPublicUrl(b.endpoint);
            if (info.ok && info.host) {
              try {
                return normalizeStoreDomain(info.host);
              } catch {
                // fall through
              }
            }
          }
        }
      }
    }
  }
  return "nordic-roast.shop";
}

function inferPlatform(ucpObj) {
  if (isPlainObject(ucpObj) && isPlainObject(ucpObj.services)) {
    const shopping = ucpObj.services["dev.ucp.shopping"];
    if (Array.isArray(shopping)) {
      const transports = shopping.filter(isPlainObject).map((b) => String(b.transport || "").toLowerCase());
      const endpoints = shopping.filter(isPlainObject).map((b) => String(b.endpoint || "").toLowerCase());
      if (endpoints.some((ep) => ep.includes("/api/ucp") || ep.includes("myshopify"))) return "shopify";
      if (transports.includes("mcp")) return "stateless_mcp";
      if (transports.includes("rest")) return "custom_rest";
    }
  }
  return "shopify";
}

function letterGrade(score) {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

export function auditUcpText(rawText) {
  if (typeof rawText !== "string" || !rawText.trim()) {
    throw new UcpParseError("Input UCP manifest text is empty.");
  }
  const cleaned = stripJsoncComments(rawText).trim();
  let parsed;
  try {
    parsed = JSON.parse(cleaned);
  } catch (err) {
    throw new UcpParseError(`Invalid JSON in UCP input: ${err.message}`);
  }
  if (!isPlainObject(parsed)) {
    throw new UcpParseError("Root UCP payload must be a JSON object.");
  }
  return auditUcpReadiness(parsed);
}

export function auditUcpReadiness(payload) {
  if (!isPlainObject(payload)) {
    throw new UcpParseError("UCP payload must be a dictionary.");
  }

  let bundle;
  let manifestDoc;
  if ("manifest" in payload && isPlainObject(payload.manifest)) {
    bundle = { ...payload };
    manifestDoc = payload.manifest;
  } else if ("ucp" in payload) {
    bundle = { ...payload };
    manifestDoc = { ucp: payload.ucp };
  } else {
    bundle = { ...payload };
    manifestDoc = payload.manifest !== undefined ? payload.manifest : payload;
  }

  const ucpObj = isPlainObject(manifestDoc) && isPlainObject(manifestDoc.ucp) ? manifestDoc.ucp : null;
  const inferredDomain = inferStoreDomain(bundle, ucpObj);
  const inferredPlatform = String(bundle.platform || inferPlatform(ucpObj));
  const gates = [];

  // UCP-01
  const g1Findings = [];
  let rootVersion = null;
  let g1Status = "fail";
  let g1Summary = "";

  if (!ucpObj) {
    g1Findings.push({
      code: "MISSING_UCP_ENVELOPE",
      severity: "critical",
      title: "Missing top-level 'ucp' JSON object in /.well-known/ucp.",
      remediation: "Wrap protocol version, services, capabilities, and payment_handlers inside {\"ucp\": {...}}."
    });
    g1Summary = "Manifest lacks the required top-level 'ucp' object.";
  } else {
    const rawVer = ucpObj.version;
    const verCheck = isValidCalendarDate(rawVer);
    if (!verCheck.ok || !verCheck.clean) {
      g1Findings.push({
        code: "INVALID_UCP_VERSION_FORMAT",
        severity: "critical",
        title: `ucp.version must be a valid YYYY-MM-DD calendar date (got ${JSON.stringify(rawVer)}).`,
        remediation: `Set "version": "${DEFAULT_UCP_VERSION}" on the root ucp object.`
      });
    } else if (verCheck.clean < "2026-01-01") {
      rootVersion = verCheck.clean;
      g1Findings.push({
        code: "OUTDATED_PRE_2026_UCP_VERSION",
        severity: "high",
        title: `ucp.version ${verCheck.clean} predates the 2026-01-23 UCP public specification.`,
        remediation: `Upgrade ucp.version to "${DEFAULT_UCP_VERSION}" or newer.`
      });
    } else {
      rootVersion = verCheck.clean;
    }

    for (const secName of ["services", "capabilities"]) {
      if (!isPlainObject(ucpObj[secName])) {
        g1Findings.push({
          code: `INVALID_${secName.toUpperCase()}_OBJECT`,
          severity: "critical",
          title: `ucp.${secName} must be a JSON object mapping reverse-domain keys to descriptor arrays.`,
          remediation: `Define ucp.${secName} as a non-empty JSON object.`
        });
      }
    }

    const hasCritG1 = g1Findings.some((f) => f.severity === "critical" || f.severity === "high");
    if (!hasCritG1 && rootVersion !== null) {
      let driftCount = 0;
      for (const secName of ["services", "capabilities", "payment_handlers"]) {
        const secVal = ucpObj[secName];
        if (isPlainObject(secVal)) {
          for (const items of Object.values(secVal)) {
            if (Array.isArray(items)) {
              for (const item of items) {
                if (isPlainObject(item)) {
                  const iv = isValidCalendarDate(item.version);
                  if (!iv.ok || iv.clean !== rootVersion) driftCount += 1;
                }
              }
            }
          }
        }
      }
      if (driftCount > 0) {
        g1Findings.push({
          code: "DESCRIPTOR_VERSION_DRIFT",
          severity: "medium",
          title: `${driftCount} descriptor(s) omit or mismatch root ucp.version (${rootVersion}).`,
          remediation: `Align every service, capability, and payment_handler version to "${rootVersion}".`
        });
        g1Status = "warn";
        g1Summary = `Root ucp.version (${rootVersion}) is valid, but ${driftCount} child descriptor(s) drift.`;
      } else {
        g1Status = "pass";
        g1Summary = `Valid ucp.version (${rootVersion}) and aligned top-level envelope.`;
      }
    } else {
      g1Status = "fail";
      g1Summary = "Invalid ucp.version date or malformed top-level UCP envelope.";
    }
  }
  gates.push(makeGateResult(0, g1Status, g1Summary, g1Findings));

  const servicesObj = ucpObj && isPlainObject(ucpObj.services) ? ucpObj.services : {};
  const capsObj = ucpObj && isPlainObject(ucpObj.capabilities) ? ucpObj.capabilities : {};
  let handlersObj = {};
  let usedLegacyPaymentBlock = false;
  if (ucpObj) {
    if (isPlainObject(ucpObj.payment_handlers)) {
      handlersObj = ucpObj.payment_handlers;
    } else if (isPlainObject(ucpObj.payment) && isPlainObject(ucpObj.payment.handlers)) {
      handlersObj = ucpObj.payment.handlers;
      usedLegacyPaymentBlock = true;
    }
  }

  // UCP-02
  const g2Findings = [];
  const serviceKeys = Object.keys(servicesObj);
  const capKeys = Object.keys(capsObj);
  const handlerKeys = Object.keys(handlersObj);

  if (serviceKeys.length === 0 && capKeys.length === 0) {
    g2Findings.push({
      code: "EMPTY_NAMESPACES",
      severity: "critical",
      title: "No service or capability namespaces declared in /.well-known/ucp.",
      remediation: "Declare dev.ucp.shopping in services and dev.ucp.shopping.checkout in capabilities."
    });
  } else {
    for (const sKey of serviceKeys) {
      if (!SERVICE_NS_RE.test(sKey)) {
        g2Findings.push({
          code: "INVALID_SERVICE_NAMESPACE",
          severity: "high",
          title: `Service key '${sKey}' violates reverse-domain syntax ({tld}.{domain}.{service}).`,
          remediation: "Use lowercase reverse-domain identifiers such as 'dev.ucp.shopping'."
        });
      } else if (sKey.startsWith("dev.ucp.") && !OFFICIAL_UCP_SERVICES.has(sKey)) {
        g2Findings.push({
          code: "RESERVED_UCP_SERVICE_SQUATTING",
          severity: "high",
          title: `Service key '${sKey}' squats on reserved dev.ucp.* namespace.`,
          remediation: "Place vendor-specific services under your own reverse domain (e.g. 'shop.brand.catalog')."
        });
      } else if (TEST_TLD_PREFIXES.some((p) => sKey.startsWith(p))) {
        g2Findings.push({
          code: "TEST_TLD_NAMESPACE",
          severity: "medium",
          title: `Service namespace '${sKey}' uses a non-routable test TLD prefix.`,
          remediation: "Use a verified public reverse-domain prefix."
        });
      }
    }

    for (const cKey of capKeys) {
      const validCapSyntax = cKey === "dev.ucp.identity_linking" || CAPABILITY_NS_RE.test(cKey);
      if (!validCapSyntax) {
        g2Findings.push({
          code: "INVALID_CAPABILITY_NAMESPACE",
          severity: "high",
          title: `Capability key '${cKey}' violates 4-segment reverse-domain grammar ({tld}.{domain}.{service}.{capability}).`,
          remediation: "Rename capability to reverse-domain format such as 'dev.ucp.shopping.checkout'."
        });
      } else if (cKey.startsWith("dev.ucp.") && !OFFICIAL_UCP_CAPABILITIES.has(cKey)) {
        g2Findings.push({
          code: "RESERVED_UCP_CAPABILITY_SQUATTING",
          severity: "high",
          title: `Capability '${cKey}' squats on reserved official dev.ucp.* namespace.`,
          remediation: "Namespace custom capabilities under your merchant reverse domain (e.g. 'shop.brand.shopping.loyalty')."
        });
      } else if (TEST_TLD_PREFIXES.some((p) => cKey.startsWith(p))) {
        g2Findings.push({
          code: "TEST_TLD_NAMESPACE",
          severity: "medium",
          title: `Capability namespace '${cKey}' uses a test TLD prefix.`,
          remediation: "Use a production reverse-domain prefix."
        });
      }
    }

    for (const hKey of handlerKeys) {
      const validHandlerSyntax = hKey === "shop.pay" || HANDLER_NS_RE.test(hKey);
      if (!validHandlerSyntax) {
        g2Findings.push({
          code: "INVALID_PAYMENT_HANDLER_NAMESPACE",
          severity: "high",
          title: `Payment handler key '${hKey}' violates reverse-domain syntax.`,
          remediation: "Use canonical handler keys: 'com.google.pay', 'com.stripe.pay', or 'shop.pay'."
        });
      }
    }
  }

  let g2Status = "pass";
  let g2Summary = "";
  if (g2Findings.some((f) => f.severity === "critical" || f.severity === "high")) {
    g2Status = "fail";
    g2Summary = "One or more keys violate reverse-domain grammar or squat on reserved dev.ucp.* namespaces.";
  } else if (g2Findings.length > 0) {
    g2Status = "warn";
    g2Summary = "Reverse-domain syntax parses, with test-TLD namespace warnings.";
  } else {
    const totalNs = serviceKeys.length + capKeys.length + handlerKeys.length;
    g2Status = "pass";
    g2Summary = `All ${totalNs} service, capability, and payment_handler namespaces pass collision-safe grammar.`;
  }
  gates.push(makeGateResult(1, g2Status, g2Summary, g2Findings));

  // UCP-03
  const g3Findings = [];
  const shoppingBindings = servicesObj["dev.ucp.shopping"];
  const seenBindings = new Set();
  const validTransportsFound = [];

  if (!Array.isArray(shoppingBindings) || shoppingBindings.length === 0) {
    g3Findings.push({
      code: "MISSING_SHOPPING_SERVICE",
      severity: "critical",
      title: "ucp.services['dev.ucp.shopping'] is missing or empty.",
      remediation: "Declare at least one HTTPS 'rest' or 'mcp' transport binding under dev.ucp.shopping."
    });
  } else {
    shoppingBindings.forEach((binding, idx) => {
      if (!isPlainObject(binding)) {
        g3Findings.push({
          code: "MALFORMED_SERVICE_BINDING",
          severity: "high",
          title: `dev.ucp.shopping[${idx}] must be a JSON object.`,
          remediation: "Provide version, spec, transport, endpoint, and schema fields."
        });
        return;
      }

      const transport = String(binding.transport || "").trim().toLowerCase();
      if (!ALLOWED_TRANSPORTS.has(transport)) {
        g3Findings.push({
          code: "UNSUPPORTED_SERVICE_TRANSPORT",
          severity: "high",
          title: `dev.ucp.shopping[${idx}] uses unsupported transport '${transport}'.`,
          remediation: "Set transport to 'rest', 'mcp', or 'a2a'."
        });
      } else if (!validTransportsFound.includes(transport)) {
        validTransportsFound.push(transport);
      }

      const epInfo = inspectHttpsPublicUrl(binding.endpoint);
      if (!epInfo.ok) {
        g3Findings.push({
          code: `ENDPOINT_${epInfo.reason}`,
          severity: "critical",
          title: `dev.ucp.shopping[${idx}].endpoint rejected: ${epInfo.detail}`,
          remediation: "Expose UCP endpoints exclusively over public TLS (https://) on a routable domain."
        });
      } else if (epInfo.has_fragment) {
        g3Findings.push({
          code: "ENDPOINT_URI_FRAGMENT",
          severity: "high",
          title: `dev.ucp.shopping[${idx}].endpoint must not contain a #fragment.`,
          remediation: "Remove URL fragments from service endpoints."
        });
      }

      const scInfo = inspectHttpsPublicUrl(binding.schema);
      if (!scInfo.ok) {
        g3Findings.push({
          code: `SCHEMA_${scInfo.reason}`,
          severity: "high",
          title: `dev.ucp.shopping[${idx}].schema rejected: ${scInfo.detail}`,
          remediation: "Reference a public https:// OpenAPI or OpenRPC JSON schema URL."
        });
      }

      if (binding.spec === undefined || binding.spec === null || String(binding.spec).trim() === "") {
        g3Findings.push({
          code: "MISSING_SERVICE_SPEC_URL",
          severity: "medium",
          title: `dev.ucp.shopping[${idx}] omits 'spec' documentation URL.`,
          remediation: "Add \"spec\": \"https://ucp.dev/specification/overview\"."
        });
      } else {
        const spInfo = inspectHttpsPublicUrl(binding.spec);
        if (!spInfo.ok) {
          g3Findings.push({
            code: `SPEC_${spInfo.reason}`,
            severity: "high",
            title: `dev.ucp.shopping[${idx}].spec rejected: ${spInfo.detail}`,
            remediation: "Use an https:// specification URL."
          });
        }
      }

      if (epInfo.ok && transport) {
        const pairKey = `${transport}|${String(binding.endpoint).trim()}`;
        if (seenBindings.has(pairKey)) {
          g3Findings.push({
            code: "DUPLICATE_SERVICE_BINDING",
            severity: "medium",
            title: `Duplicate (${transport}, ${String(binding.endpoint).trim()}) binding in dev.ucp.shopping.`,
            remediation: "Deduplicate identical transport + endpoint entries."
          });
        }
        seenBindings.add(pairKey);
      }
    });
  }

  let g3Status = "pass";
  let g3Summary = "";
  if (g3Findings.some((f) => f.severity === "critical" || f.severity === "high")) {
    g3Status = "fail";
    g3Summary = "Service bindings failed HTTPS-only, SSRF/private-IP, transport, or schema checks.";
  } else if (g3Findings.length > 0) {
    g3Status = "warn";
    g3Summary = "Service endpoints are public HTTPS, with minor spec/duplication warnings.";
  } else {
    g3Status = "pass";
    g3Summary = `Verified public HTTPS endpoints and schemas across ${validTransportsFound.join(", ")} transport(s).`;
  }
  gates.push(makeGateResult(2, g3Status, g3Summary, g3Findings));

  // UCP-04
  const g4Findings = [];
  const checkoutList = capsObj["dev.ucp.shopping.checkout"];
  if (!Array.isArray(checkoutList) || checkoutList.length === 0) {
    g4Findings.push({
      code: "MISSING_CHECKOUT_CAPABILITY",
      severity: "critical",
      title: "Core capability 'dev.ucp.shopping.checkout' is missing from ucp.capabilities.",
      remediation: "Declare dev.ucp.shopping.checkout with version, spec, and https:// checkout.json schema."
    });
  } else {
    for (const [capKey, descList] of Object.entries(capsObj)) {
      if (!Array.isArray(descList) || descList.length === 0) {
        g4Findings.push({
          code: "EMPTY_CAPABILITY_DESCRIPTORS",
          severity: "high",
          title: `Capability '${capKey}' must contain a non-empty array of descriptors.`,
          remediation: `Provide at least one descriptor object for ${capKey}.`
        });
        continue;
      }
      descList.forEach((desc, idx) => {
        if (!isPlainObject(desc)) {
          g4Findings.push({
            code: "MALFORMED_CAPABILITY_DESCRIPTOR",
            severity: "high",
            title: `${capKey}[${idx}] must be a JSON object.`,
            remediation: "Provide version, spec, and schema fields."
          });
          return;
        }
        const spCheck = inspectHttpsPublicUrl(desc.spec);
        const scCheck = inspectHttpsPublicUrl(desc.schema);
        if (!spCheck.ok) {
          g4Findings.push({
            code: "INVALID_CAPABILITY_SPEC_URL",
            severity: "high",
            title: `${capKey}[${idx}].spec invalid: ${spCheck.detail}`,
            remediation: "Set spec to a public https:// specification URL."
          });
        }
        if (!scCheck.ok) {
          g4Findings.push({
            code: "INVALID_CAPABILITY_SCHEMA_URL",
            severity: "high",
            title: `${capKey}[${idx}].schema invalid: ${scCheck.detail}`,
            remediation: "Set schema to a public https:// JSON Schema URL."
          });
        } else {
          const schemaStr = String(desc.schema || "").trim();
          if (!schemaStr.toLowerCase().endsWith(".json")) {
            g4Findings.push({
              code: "NON_JSON_CAPABILITY_SCHEMA_PATH",
              severity: "medium",
              title: `${capKey}[${idx}].schema (${schemaStr}) does not end with .json.`,
              remediation: "Point capability schema to an explicit .json JSON Schema artifact."
            });
          }
          const dv = isValidCalendarDate(desc.version);
          const embeddedDates = [...schemaStr.matchAll(EMBEDDED_DATE_RE)].map((m) => m[1]);
          if (dv.ok && dv.clean && embeddedDates.length > 0 && !embeddedDates.includes(dv.clean)) {
            g4Findings.push({
              code: "CAPABILITY_SCHEMA_VERSION_MISMATCH",
              severity: "medium",
              title: `${capKey}[${idx}] version (${dv.clean}) mismatches schema URL date (${embeddedDates[0]}).`,
              remediation: `Use matching ${dv.clean} schema path in ${capKey}.`
            });
          }
        }
      });
    }
  }

  let g4Status = "pass";
  let g4Summary = "";
  if (g4Findings.some((f) => f.severity === "critical" || f.severity === "high")) {
    g4Status = "fail";
    g4Summary = "Core dev.ucp.shopping.checkout is missing or capability spec/schema URLs are invalid.";
  } else if (g4Findings.length > 0) {
    g4Status = "warn";
    g4Summary = "dev.ucp.shopping.checkout is present, with minor schema path/version alignment warnings.";
  } else {
    g4Status = "pass";
    g4Summary = `dev.ucp.shopping.checkout and ${capKeys.length} total capability contract(s) verified.`;
  }
  gates.push(makeGateResult(3, g4Status, g4Summary, g4Findings));

  // UCP-05
  const dagInfo = inspectCapabilityDag(capsObj);
  const g5Findings = [];

  if (capKeys.length === 0) {
    g5Findings.push({
      code: "EMPTY_CAPABILITY_DAG",
      severity: "critical",
      title: "Cannot verify capability composition graph because ucp.capabilities is empty.",
      remediation: "Declare dev.ucp.shopping.checkout and its extension DAG."
    });
  }
  for (const inv of dagInfo.invalid_extends) {
    g5Findings.push({
      code: "INVALID_EXTENDS_FIELD",
      severity: "high",
      title: `${inv.capability}: ${inv.detail}`,
      remediation: "Set extends to a parent capability namespace string (e.g. 'dev.ucp.shopping.checkout')."
    });
  }
  for (const dang of dagInfo.dangling_parents) {
    g5Findings.push({
      code: "DANGLING_EXTENDS_PARENT",
      severity: "critical",
      title: `Capability '${dang.capability}' extends undeclared parent '${dang.missing_parent}'.`,
      remediation: `Declare '${dang.missing_parent}' in ucp.capabilities or fix the extends target.`
    });
  }
  for (const cyc of dagInfo.cycles) {
    g5Findings.push({
      code: "CAPABILITY_EXTENDS_CYCLE",
      severity: "critical",
      title: `Cycle detected in capability extends graph: ${cyc.join(" -> ")}.`,
      remediation: "Break circular extends references so capability inheritance forms a strict DAG rooted at checkout."
    });
  }
  for (const orphanExt of dagInfo.missing_checkout_inheritance) {
    g5Findings.push({
      code: "MISSING_CANONICAL_CHECKOUT_EXTENDS",
      severity: "medium",
      title: `Extension '${orphanExt}' omits "extends": "dev.ucp.shopping.checkout".`,
      remediation: `Add "extends": "dev.ucp.shopping.checkout" to ${orphanExt}.`
    });
  }

  let g5Status = "pass";
  let g5Summary = "";
  if (g5Findings.some((f) => f.severity === "critical" || f.severity === "high")) {
    g5Status = "fail";
    g5Summary = "Capability inheritance graph contains cycles, dangling parents, or invalid extends syntax.";
  } else if (g5Findings.length > 0) {
    g5Status = "warn";
    g5Summary = "Capability graph is acyclic, but standard shopping extensions omit explicit checkout inheritance.";
  } else {
    g5Status = "pass";
    g5Summary = `Acyclic capability DAG verified (${dagInfo.nodes.length} node(s), ${dagInfo.edges.length} extends edge(s)).`;
  }
  gates.push(makeGateResult(4, g5Status, g5Summary, g5Findings));

  // UCP-06
  const g6Findings = [];
  if (usedLegacyPaymentBlock) {
    g6Findings.push({
      code: "LEGACY_NESTED_PAYMENT_HANDLERS",
      severity: "medium",
      title: "Manifest uses nested ucp.payment.handlers instead of canonical ucp.payment_handlers.",
      remediation: "Promote payment handlers to top-level ucp.payment_handlers."
    });
  }

  const rawHandlersDump = JSON.stringify(handlersObj);
  const secretMatch = rawHandlersDump.match(SECRET_LEAK_RE);
  if (secretMatch) {
    const leakedPrefix = secretMatch[0].slice(0, 10) + "...";
    g6Findings.push({
      code: "LEAKED_PSP_SECRET_IN_MANIFEST",
      severity: "critical",
      title: `Private PSP/Shopify secret token (${leakedPrefix}) exposed in public /.well-known/ucp!`,
      remediation: "Immediately revoke the leaked token and publish only public handler schemas/identifiers."
    });
  }

  const seenHandlerUuids = new Set();
  if (handlerKeys.length === 0) {
    g6Findings.push({
      code: "MISSING_PAYMENT_HANDLERS",
      severity: "critical",
      title: "ucp.payment_handlers is missing or empty.",
      remediation: "Advertise at least one tokenized payment handler (e.g. com.google.pay, com.stripe.pay, shop.pay)."
    });
  } else {
    for (const [hKey, hList] of Object.entries(handlersObj)) {
      if (!Array.isArray(hList) || hList.length === 0) {
        g6Findings.push({
          code: "EMPTY_PAYMENT_HANDLER_ARRAY",
          severity: "high",
          title: `payment_handlers['${hKey}'] must be a non-empty array.`,
          remediation: `Provide a handler descriptor with UUID id, version, spec, and schema for ${hKey}.`
        });
        continue;
      }
      hList.forEach((hDesc, idx) => {
        if (!isPlainObject(hDesc)) {
          g6Findings.push({
            code: "MALFORMED_PAYMENT_HANDLER",
            severity: "high",
            title: `payment_handlers['${hKey}'][${idx}] must be an object.`,
            remediation: "Provide id, version, spec, and config_schema/schema."
          });
          return;
        }
        const rawId = String(hDesc.id || "").trim();
        if (!rawId) {
          g6Findings.push({
            code: "MISSING_HANDLER_ID",
            severity: "high",
            title: `payment_handlers['${hKey}'][${idx}] is missing 'id'.`,
            remediation: "Assign a deterministic RFC 4122 UUID to each payment handler entry."
          });
        } else if (!UUID_RE.test(rawId)) {
          g6Findings.push({
            code: "NON_UUID_HANDLER_ID",
            severity: "medium",
            title: `payment_handlers['${hKey}'][${idx}].id ('${rawId}') is not an RFC 4122 UUID.`,
            remediation: "Use a standard RFC 4122 UUID (e.g. UUIDv5 derived from merchant domain + handler)."
          });
        } else {
          const normUuid = rawId.toLowerCase();
          if (seenHandlerUuids.has(normUuid)) {
            g6Findings.push({
              code: "DUPLICATE_HANDLER_UUID",
              severity: "high",
              title: `Duplicate payment handler UUID ${normUuid} across handlers.`,
              remediation: "Assign a distinct UUID per payment handler configuration."
            });
          }
          seenHandlerUuids.add(normUuid);
        }

        const hv = isValidCalendarDate(hDesc.version);
        if (!hv.ok) {
          g6Findings.push({
            code: "INVALID_HANDLER_VERSION",
            severity: "high",
            title: `payment_handlers['${hKey}'][${idx}].version must be YYYY-MM-DD.`,
            remediation: `Set handler version to "${rootVersion || DEFAULT_UCP_VERSION}".`
          });
        }

        const spInfo = inspectHttpsPublicUrl(hDesc.spec);
        if (!spInfo.ok) {
          g6Findings.push({
            code: "INVALID_HANDLER_SPEC_URL",
            severity: "high",
            title: `payment_handlers['${hKey}'][${idx}].spec invalid: ${spInfo.detail}`,
            remediation: "Provide a public https:// handler specification URL."
          });
        }

        const cfgSchemaRaw = hDesc.config_schema || hDesc.schema;
        const csInfo = inspectHttpsPublicUrl(cfgSchemaRaw);
        if (!csInfo.ok) {
          g6Findings.push({
            code: "INVALID_HANDLER_SCHEMA_URL",
            severity: "high",
            title: `payment_handlers['${hKey}'][${idx}] schema/config_schema invalid: ${csInfo.detail}`,
            remediation: "Provide a public https:// JSON Schema URL for handler configuration."
          });
        }

        if (hDesc.instrument_schemas !== undefined && hDesc.instrument_schemas !== null) {
          if (!Array.isArray(hDesc.instrument_schemas) || hDesc.instrument_schemas.length === 0) {
            g6Findings.push({
              code: "EMPTY_INSTRUMENT_SCHEMAS",
              severity: "medium",
              title: `payment_handlers['${hKey}'][${idx}].instrument_schemas is empty.`,
              remediation: "Provide at least one https:// payment instrument schema URL."
            });
          } else {
            for (const isUrl of hDesc.instrument_schemas) {
              const isInfo = inspectHttpsPublicUrl(isUrl);
              if (!isInfo.ok) {
                g6Findings.push({
                  code: "INVALID_INSTRUMENT_SCHEMA_URL",
                  severity: "high",
                  title: `payment_handlers['${hKey}'][${idx}] instrument_schema invalid: ${isInfo.detail}`,
                  remediation: "Ensure all instrument_schemas use public https:// URLs."
                });
              }
            }
          }
        }
      });
    }
  }

  let g6Status = "pass";
  let g6Summary = "";
  if (g6Findings.some((f) => f.severity === "critical" || f.severity === "high")) {
    g6Status = "fail";
    g6Summary = "Payment handlers missing, exposing raw secrets, or failing HTTPS schema/version validation.";
  } else if (g6Findings.length > 0) {
    g6Status = "warn";
    g6Summary = "Payment handlers are HTTPS-backed, with UUID format or legacy key warnings.";
  } else {
    g6Status = "pass";
    g6Summary = `Verified ${handlerKeys.length} payment handler(s) (${handlerKeys.join(", ")}) with UUIDs and HTTPS schemas.`;
  }
  gates.push(makeGateResult(5, g6Status, g6Summary, g6Findings));

  // UCP-07
  const g7Findings = [];
  const mcpBindings = [];
  const restBindings = [];
  if (Array.isArray(shoppingBindings)) {
    for (const b of shoppingBindings) {
      if (isPlainObject(b)) {
        const t = String(b.transport || "").trim().toLowerCase();
        if (t === "mcp") mcpBindings.push(b);
        else if (t === "rest") restBindings.push(b);
      }
    }
  }

  if (mcpBindings.length === 0 && restBindings.length === 0) {
    g7Findings.push({
      code: "NO_REST_OR_MCP_SURFACE",
      severity: "high",
      title: "Neither REST OpenAPI nor Stateless MCP transport surface is available on dev.ucp.shopping.",
      remediation: "Expose an HTTPS REST OpenAPI surface and/or Stateless MCP Streamable HTTP (/mcp) surface."
    });
  }

  mcpBindings.forEach((mb, idx) => {
    const epStr = String(mb.endpoint || "").trim();
    const scStr = String(mb.schema || "").trim();
    const cfg = isPlainObject(mb.config) ? mb.config : {};
    if (epStr.toLowerCase().endsWith("/sse") || epStr.toLowerCase().includes("/sse?")) {
      g7Findings.push({
        code: "DEPRECATED_MCP_SSE_TRANSPORT",
        severity: "high",
        title: `MCP binding[${idx}] uses deprecated stateful HTTP+SSE endpoint (${epStr}).`,
        remediation: `Migrate to Stateless Streamable HTTP (/mcp) aligned with MCP ${MCP_STATELESS_REVISION}.`
      });
    }
    if (!scStr.toLowerCase().endsWith(".json")) {
      g7Findings.push({
        code: "MISSING_MCP_OPENRPC_JSON",
        severity: "high",
        title: `MCP binding[${idx}] lacks a .json OpenRPC/MCP tool contract schema URL.`,
        remediation: "Point MCP schema to https://ucp.dev/2026-01-23/services/shopping/openrpc.json."
      });
    }
    const mcpRev = String(cfg.mcp_protocol_version || "");
    const statelessFlag = cfg.stateless_streamable_http;
    if (statelessFlag === false) {
      g7Findings.push({
        code: "STATEFUL_MCP_SESSION_COUPLING",
        severity: "high",
        title: "MCP transport explicitly disables stateless_streamable_http.",
        remediation: `Enable stateless Streamable HTTP (${MCP_STATELESS_REVISION}) for horizontally scalable checkout.`
      });
    } else if (restBindings.length === 0 && mcpRev < "2026-01-01" && statelessFlag !== true) {
      g7Findings.push({
        code: "MCP_WITHOUT_OPENAPI_OR_STATELESS_DECLARATION",
        severity: "medium",
        title: "MCP transport is advertised without companion REST OpenAPI binding or explicit 2026-07-28 stateless config.",
        remediation: "Add a companion REST OpenAPI binding or declare config.mcp_protocol_version = '2026-07-28'."
      });
    }
  });

  restBindings.forEach((rb, idx) => {
    const scStr = String(rb.schema || "").trim();
    if (scStr && !scStr.toLowerCase().endsWith(".json")) {
      g7Findings.push({
        code: "NON_JSON_REST_OPENAPI_SCHEMA",
        severity: "medium",
        title: `REST binding[${idx}] schema (${scStr}) does not reference a .json OpenAPI specification.`,
        remediation: "Point REST schema to an explicit openapi.json URL."
      });
    }
  });

  const agentCard = bundle.agent_card !== undefined ? bundle.agent_card : null;
  if (agentCard !== null) {
    if (!isPlainObject(agentCard)) {
      g7Findings.push({
        code: "MALFORMED_A2A_AGENT_CARD",
        severity: "high",
        title: "/.well-known/agent.json must be a JSON object.",
        remediation: "Provide name, url (https://), version, and skills array in /.well-known/agent.json."
      });
    } else {
      const acUrlInfo = inspectHttpsPublicUrl(agentCard.url);
      if (!acUrlInfo.ok) {
        g7Findings.push({
          code: "INVALID_A2A_AGENT_URL",
          severity: "high",
          title: `/.well-known/agent.json url rejected: ${acUrlInfo.detail}`,
          remediation: "Serve A2A agent endpoint over public https:// with zero private-IP/localhost targets."
        });
      }
      if (!Array.isArray(agentCard.skills) || agentCard.skills.length === 0) {
        g7Findings.push({
          code: "EMPTY_A2A_SKILLS",
          severity: "medium",
          title: "/.well-known/agent.json declares zero skills.",
          remediation: "Declare commerce skills (e.g. ucp-shopping-checkout) in agent.json skills[]."
        });
      }
    }
  }

  let g7Status = "pass";
  let g7Summary = "";
  if (g7Findings.some((f) => f.severity === "critical" || f.severity === "high")) {
    g7Status = "fail";
    g7Summary = "MCP / OpenAPI / A2A surface failed stateless transport or HTTPS contract validation.";
  } else if (g7Findings.length > 0) {
    g7Status = "warn";
    g7Summary = "Transport surface is reachable, with dual-surface parity or OpenAPI/A2A warnings.";
  } else {
    const surfaceLabels = [];
    if (restBindings.length > 0) surfaceLabels.push("REST OpenAPI");
    if (mcpBindings.length > 0) surfaceLabels.push(`Stateless MCP (${MCP_STATELESS_REVISION})`);
    if (isPlainObject(agentCard)) surfaceLabels.push("A2A agent.json");
    g7Status = "pass";
    g7Summary = `Surface parity verified across ${surfaceLabels.join(" + ")}.`;
  }
  gates.push(makeGateResult(6, g7Status, g7Summary, g7Findings));

  // UCP-08
  const g8Findings = [];
  let checkoutCfg = {};
  const fallbackCheckoutList = Array.isArray(checkoutList) && checkoutList.length > 0 ? checkoutList : capsObj.checkout;
  if (Array.isArray(fallbackCheckoutList) && fallbackCheckoutList.length > 0 && isPlainObject(fallbackCheckoutList[0])) {
    if (isPlainObject(fallbackCheckoutList[0].config)) {
      checkoutCfg = fallbackCheckoutList[0].config;
    }
  }

  const rawUcpCurrencies = checkoutCfg.supported_currencies;
  const ucpCurrencies = [];
  if (Array.isArray(rawUcpCurrencies)) {
    for (const c of rawUcpCurrencies) {
      const code = String(c || "").trim().toUpperCase();
      if (!ISO_4217_CURRENCIES.has(code)) {
        g8Findings.push({
          code: "INVALID_UCP_ISO4217_CURRENCY",
          severity: "high",
          title: `Checkout config declares invalid ISO 4217 currency '${c}'.`,
          remediation: "Use 3-letter uppercase ISO 4217 codes such as 'USD', 'JPY', or 'EUR'."
        });
      } else if (!ucpCurrencies.includes(code)) {
        ucpCurrencies.push(code);
      }
    }
  }

  const detectedOffers = [];
  if (Array.isArray(bundle.schema_org_offers)) {
    for (const item of bundle.schema_org_offers) {
      if (isPlainObject(item)) {
        detectedOffers.push({
          name: String(item.name || "Product"),
          sku: String(item.sku || ""),
          price: item.price,
          price_currency: String(item.price_currency || item.priceCurrency || "").trim(),
          availability: String(item.availability || "").trim()
        });
      }
    }
  }
  if (typeof bundle.html === "string" && bundle.html.trim()) {
    detectedOffers.push(...extractSchemaOrgOffersFromHtml(bundle.html));
  }

  detectedOffers.forEach((off, idx) => {
    const cur = String(off.price_currency || "").trim();
    if (!cur || cur !== cur.toUpperCase() || !ISO_4217_CURRENCIES.has(cur)) {
      g8Findings.push({
        code: "INVALID_OFFER_CURRENCY",
        severity: "high",
        title: `Schema.org Offer[${idx}] has missing or non-ISO-4217 priceCurrency ('${cur}').`,
        remediation: "Set Offer.priceCurrency to an exact ISO 4217 uppercase code matching UCP checkout."
      });
    } else if (ucpCurrencies.length > 0 && !ucpCurrencies.includes(cur)) {
      g8Findings.push({
        code: "OFFER_UCP_CURRENCY_MISMATCH",
        severity: "critical",
        title: `Hallucination trap: Schema.org Offer[${idx}] advertises ${cur}, but UCP checkout only accepts [${ucpCurrencies.map((x) => `'${x}'`).join(", ")}].`,
        remediation: `Align Offer.priceCurrency (${cur}) with ucp.capabilities['dev.ucp.shopping.checkout'][0].config.supported_currencies.`
      });
    }

    const rawPrice = off.price;
    const cleanedPrice = rawPrice === null || rawPrice === undefined ? "" : String(rawPrice).replace(/,/g, "").trim();
    const numPrice = cleanedPrice === "" ? NaN : Number(cleanedPrice);
    if (Number.isNaN(numPrice) || numPrice < 0) {
      g8Findings.push({
        code: "INVALID_OFFER_PRICE",
        severity: "high",
        title: `Schema.org Offer[${idx}] has non-numeric or negative price (${JSON.stringify(rawPrice)}).`,
        remediation: "Format Offer.price as a non-negative decimal string (e.g. '34.00' or '4800')."
      });
    }

    const avail = String(off.availability || "").trim();
    const availSlug = avail ? avail.split("/").pop().toLowerCase() : "";
    if (!VALID_SCHEMA_AVAILABILITIES.has(availSlug)) {
      g8Findings.push({
        code: "MISSING_OFFER_AVAILABILITY",
        severity: "medium",
        title: `Schema.org Offer[${idx}] omits standard availability URI (got '${avail}').`,
        remediation: "Include \"availability\": \"https://schema.org/InStock\" (or OutOfStock/PreOrder) to prevent stock hallucination."
      });
    }
  });

  if (detectedOffers.length === 0 && ucpCurrencies.length === 0) {
    if (!Array.isArray(checkoutList) || checkoutList.length === 0) {
      g8Findings.push({
        code: "NO_CHECKOUT_CURRENCY_CONTRACT",
        severity: "high",
        title: "No checkout capability or Schema.org Offer currency metadata available.",
        remediation: "Declare dev.ucp.shopping.checkout with ISO 4217 supported_currencies and matching Schema.org Offer JSON-LD."
      });
    } else {
      g8Findings.push({
        code: "IMPLICIT_CHECKOUT_CURRENCY",
        severity: "medium",
        title: "Neither Schema.org Offer nor checkout config.supported_currencies specifies ISO 4217 currencies.",
        remediation: "Add config.supported_currencies (e.g. ['USD']) on dev.ucp.shopping.checkout to prevent agent FX guessing."
      });
    }
  }

  let g8Status = "pass";
  let g8Summary = "";
  if (g8Findings.some((f) => f.severity === "critical" || f.severity === "high")) {
    g8Status = "fail";
    g8Summary = "Price/currency mismatch or invalid Schema.org Offer detected (agentic checkout hallucination risk).";
  } else if (g8Findings.length > 0) {
    g8Status = "warn";
    g8Summary = "No currency conflict found, but explicit ISO 4217 currency or availability metadata is incomplete.";
  } else {
    const curSummary = ucpCurrencies.length > 0 ? ucpCurrencies.join(", ") : detectedOffers[0].price_currency;
    g8Status = "pass";
    g8Summary = `ISO 4217 currency (${curSummary}) and inventory parity verified (${detectedOffers.length} Offer(s) cross-checked).`;
  }
  gates.push(makeGateResult(7, g8Status, g8Summary, g8Findings));

  // UCP-09
  const g9Findings = [];
  const ap2List = capsObj["dev.ucp.shopping.ap2_mandate"];
  const hasAp2Cap = Array.isArray(ap2List) && ap2List.length > 0;
  const ap2Cfg = hasAp2Cap && isPlainObject(ap2List[0]) && isPlainObject(ap2List[0].config) ? ap2List[0].config : {};

  if (checkoutCfg.allow_unverified_agent_autocharge === true) {
    g9Findings.push({
      code: "UNVERIFIED_AGENT_AUTOCHARGE_ENABLED",
      severity: "critical",
      title: "Checkout explicitly permits unverified autonomous agent auto-charging without AP2 mandate!",
      remediation: "Remove allow_unverified_agent_autocharge and require cryptographic AP2 CheckoutMandate / PaymentMandate."
    });
  }
  if (checkoutCfg.idempotency_key_required === false) {
    g9Findings.push({
      code: "IDEMPOTENCY_PROTECTION_DISABLED",
      severity: "critical",
      title: "Checkout explicitly disables Idempotency-Key deduplication (severe agent double-charge risk).",
      remediation: "Require Idempotency-Key on REST complete_checkout and meta['idempotency-key'] on MCP tool calls."
    });
  }
  if (checkoutCfg.ap2_mandate_required === false || ap2Cfg.require_user_signature === false) {
    g9Findings.push({
      code: "AP2_USER_SIGNATURE_DISABLED",
      severity: "high",
      title: "AP2 user mandate signature verification is explicitly disabled.",
      remediation: "Enforce ap2_mandate_required = true and require_user_signature = true."
    });
  }

  if (g9Findings.length === 0) {
    if (!Array.isArray(checkoutList) || checkoutList.length === 0) {
      g9Findings.push({
        code: "NO_CHECKOUT_FOR_AP2_MANDATE",
        severity: "high",
        title: "Cannot enforce AP2 mandates or idempotency without dev.ucp.shopping.checkout.",
        remediation: "Declare dev.ucp.shopping.checkout + dev.ucp.shopping.ap2_mandate."
      });
    } else {
      const hasExplicitIdempotency = checkoutCfg.idempotency_key_required === true;
      const hasAp2Guard = hasAp2Cap || checkoutCfg.ap2_mandate_required === true;
      if (!hasAp2Guard) {
        g9Findings.push({
          code: "MISSING_AP2_MANDATE_CAPABILITY",
          severity: "medium",
          title: "No dev.ucp.shopping.ap2_mandate extension or ap2_mandate_required guardrail advertised.",
          remediation: "Add dev.ucp.shopping.ap2_mandate (extending checkout) to verify cryptographic CheckoutMandate & SD-JWT-VC."
        });
      }
      if (!hasExplicitIdempotency && !hasAp2Cap) {
        g9Findings.push({
          code: "UNSPECIFIED_IDEMPOTENCY_POLICY",
          severity: "medium",
          title: "Checkout omits explicit idempotency-key replay protection metadata.",
          remediation: "Set config.idempotency_key_required = true (and MCP meta['idempotency-key']) to prevent retry double-charges."
        });
      }
    }
  }

  let g9Status = "pass";
  let g9Summary = "";
  if (g9Findings.some((f) => f.severity === "critical" || f.severity === "high")) {
    g9Status = "fail";
    g9Summary = "AP2 payment mandate or idempotency protection is disabled or missing core checkout.";
  } else if (g9Findings.length > 0) {
    g9Status = "warn";
    g9Summary = "Checkout exists, but explicit AP2 mandate capability or idempotency replay policy should be added.";
  } else {
    g9Status = "pass";
    g9Summary = "AP2 cryptographic mandate verification and idempotency-key replay protection verified.";
  }
  gates.push(makeGateResult(8, g9Status, g9Summary, g9Findings));

  // UCP-10
  const g10Findings = [];
  const normHeaders = {};
  if (isPlainObject(bundle.http_headers)) {
    for (const [k, v] of Object.entries(bundle.http_headers)) {
      normHeaders[String(k).trim().toLowerCase()] = String(v).trim();
    }
  }

  if (bundle.status_code !== undefined && bundle.status_code !== null && Number(bundle.status_code) !== 200) {
    g10Findings.push({
      code: "NON_200_DISCOVERY_STATUS",
      severity: "critical",
      title: `/.well-known/ucp returned HTTP ${bundle.status_code} instead of 200 OK.`,
      remediation: "Serve /.well-known/ucp directly with HTTP 200 over HTTPS."
    });
  }

  if (Object.keys(normHeaders).length > 0) {
    const ctype = (normHeaders["content-type"] || "").toLowerCase();
    if (!ctype.includes("application/json")) {
      g10Findings.push({
        code: "INVALID_DISCOVERY_CONTENT_TYPE",
        severity: "critical",
        title: `/.well-known/ucp served with Content-Type '${ctype}' instead of application/json.`,
        remediation: "Configure edge route to return Content-Type: application/json; charset=utf-8 (prevent SPA HTML soft-404s)."
      });
    }
    if (!normHeaders["access-control-allow-origin"]) {
      g10Findings.push({
        code: "MISSING_CORS_HEADER",
        severity: "medium",
        title: "Response headers omit Access-Control-Allow-Origin: * for cross-origin agent discovery.",
        remediation: "Add Access-Control-Allow-Origin: * on /.well-known/ucp and /.well-known/agent.json."
      });
    }
    if (!normHeaders["cache-control"]) {
      g10Findings.push({
        code: "MISSING_CACHE_CONTROL_HEADER",
        severity: "medium",
        title: "Response headers omit Cache-Control policy on /.well-known/ucp.",
        remediation: "Add Cache-Control: public, max-age=3600, stale-while-revalidate=86400."
      });
    }
  }

  if (!ucpObj || serviceKeys.length === 0 || capKeys.length === 0) {
    g10Findings.push({
      code: "MANIFEST_NOT_DEPLOY_READY",
      severity: "high",
      title: "Manifest cannot be deployed cleanly until core ucp envelope, services, and capabilities are present.",
      remediation: "Use the generated 1-Click /.well-known/ucp Manifest + Cloudflare Worker / Nginx bundle below."
    });
  }

  const genCapsFiltered = capKeys.filter((k) => OFFICIAL_UCP_CAPABILITIES.has(k));
  const genHandlersFiltered = handlerKeys.filter((k) => k === "shop.pay" || HANDLER_NS_RE.test(k));
  const offerCurs = detectedOffers
    .map((o) => String(o.price_currency || "").toUpperCase())
    .filter((c) => ISO_4217_CURRENCIES.has(c));
  const genCurrencies = ucpCurrencies.length > 0 ? ucpCurrencies : (offerCurs.length > 0 ? offerCurs : ["USD"]);

  let deploymentBundle;
  try {
    const safePlatform = ["shopify", "custom_rest", "stateless_mcp"].includes(inferredPlatform) ? inferredPlatform : "shopify";
    deploymentBundle = generateUcpBundle(inferredDomain, {
      platform: safePlatform,
      capabilities: genCapsFiltered.length > 0 ? genCapsFiltered : null,
      paymentHandlers: genHandlersFiltered.length > 0 ? genHandlersFiltered : null,
      currencies: genCurrencies,
      version: rootVersion && rootVersion >= "2026-01-01" ? rootVersion : DEFAULT_UCP_VERSION,
      includeA2aAgentCard: true
    });
  } catch {
    deploymentBundle = generateUcpBundle("nordic-roast.shop", { platform: "shopify" });
  }

  let g10Status = "pass";
  let g10Summary = "";
  if (g10Findings.some((f) => f.severity === "critical" || f.severity === "high")) {
    g10Status = "fail";
    g10Summary = "Discovery endpoint returned non-200 / non-JSON response or manifest envelope is incomplete.";
  } else if (g10Findings.length > 0) {
    g10Status = "warn";
    g10Summary = "JSON discovery payload parses, but CORS or Cache-Control edge headers are missing.";
  } else {
    g10Status = "pass";
    g10Summary = "Edge delivery contract verified and 1-Click Cloudflare Worker + Nginx bundle generated.";
  }
  gates.push(makeGateResult(9, g10Status, g10Summary, g10Findings));

  const score = gates.reduce((acc, g) => acc + g.earned_points, 0);
  const gatesPassed = gates.filter((g) => g.status === "pass").length;
  const gatesWarned = gates.filter((g) => g.status === "warn").length;
  const gatesFailed = gates.filter((g) => g.status === "fail").length;
  const findingsCount = gates.reduce((acc, g) => acc + g.findings.length, 0);

  let overallStatus = "non_compliant";
  if (gatesFailed === 0 && gatesWarned === 0) overallStatus = "compliant";
  else if (gatesFailed === 0) overallStatus = "action_required";

  return {
    domain: inferredDomain,
    ucp_version: rootVersion,
    status: overallStatus,
    score,
    grade: letterGrade(score),
    gates_passed: gatesPassed,
    gates_warned: gatesWarned,
    gates_failed: gatesFailed,
    findings_count: findingsCount,
    gates,
    dag: dagInfo,
    detected_offers: detectedOffers,
    surfaces: {
      has_ucp_manifest: Boolean(ucpObj),
      transports: validTransportsFound,
      capabilities_count: capKeys.length,
      payment_handlers_count: handlerKeys.length,
      has_a2a_agent_card: isPlainObject(agentCard),
      has_llms_txt: Boolean(typeof bundle.llms_txt === "string" && bundle.llms_txt.trim()),
      offers_count: detectedOffers.length
    },
    deployment_bundle: deploymentBundle
  };
}

export function buildSamplePresets() {
  const prodBundle = generateUcpBundle("nordic-roast.shop", {
    platform: "shopify",
    capabilities: [
      "dev.ucp.shopping.checkout",
      "dev.ucp.shopping.fulfillment",
      "dev.ucp.shopping.discount",
      "dev.ucp.shopping.order",
      "dev.ucp.shopping.ap2_mandate"
    ],
    paymentHandlers: ["com.google.pay", "com.stripe.pay", "shop.pay"],
    currencies: ["USD"],
    version: DEFAULT_UCP_VERSION,
    includeA2aAgentCard: true,
    storeName: "Nordic Roast Coffee"
  });

  return {
    "broken-shopify-draft": {
      domain: "kuroshio-craft.jp",
      platform: "shopify",
      status_code: 200,
      http_headers: {
        "Content-Type": "text/html; charset=utf-8"
      },
      manifest: {
        ucp: {
          version: "1.0",
          services: {
            "dev.ucp.shopping": [
              {
                version: "1.0",
                transport: "rest",
                endpoint: "https://kuroshio-craft.jp/api/ucp",
                schema: "https://ucp.dev/2026-01-23/services/shopping/openapi.json"
              }
            ]
          },
          capabilities: {
            checkout: [
              {
                version: "1.0",
                spec: "https://ucp.dev/specification/checkout",
                schema: "https://ucp.dev/2026-01-23/schemas/shopping/checkout.json",
                config: {
                  supported_currencies: ["USD"]
                }
              }
            ],
            "dev.ucp.shopping.discount": [
              {
                version: "2026-01-23",
                spec: "https://ucp.dev/specification/discount",
                schema: "https://ucp.dev/2026-01-23/schemas/shopping/discount.json",
                extends: "dev.ucp.shopping.checkout"
              }
            ]
          },
          payment_handlers: {
            "shop.pay": [
              {
                id: "shop_pay_draft_01",
                version: "2026-01-23",
                spec: "https://shopify.dev/docs/agents/ucp/shop-pay",
                schema: "https://shopify.dev/ucp/2026-01-23/schemas/shop_pay_config.json",
                config: {
                  admin_token: "shpat_4f9c2a8b1e7d001122334455"
                }
              }
            ]
          }
        }
      },
      schema_org_offers: [
        {
          name: "Indigo Dyed Linen Apron",
          sku: "KC-APRON-04",
          price: "12800",
          priceCurrency: "JPY",
          availability: "https://schema.org/InStock"
        }
      ]
    },
    "cyclic-http-ssrf": {
      domain: "atelier-verre.eu",
      platform: "stateless_mcp",
      status_code: 200,
      http_headers: {
        "Content-Type": "application/json"
      },
      manifest: {
        ucp: {
          version: "2026-01-23",
          services: {
            "dev.ucp.shopping": [
              {
                version: "2026-01-23",
                spec: "https://ucp.dev/specification/overview",
                transport: "rest",
                endpoint: "http://api.atelier-verre.eu/ucp/v1",
                schema: "https://ucp.dev/2026-01-23/services/shopping/openapi.json"
              },
              {
                version: "2026-01-23",
                spec: "https://ucp.dev/specification/overview",
                transport: "rest",
                endpoint: "https://10.0.4.22:8443/ucp/internal",
                schema: "https://ucp.dev/2026-01-23/services/shopping/openapi.json"
              },
              {
                version: "2026-01-23",
                spec: "https://ucp.dev/specification/mcp",
                transport: "mcp",
                endpoint: "https://atelier-verre.eu/ucp/sse",
                schema: "https://atelier-verre.eu/ucp/mcp-docs"
              }
            ]
          },
          capabilities: {
            "dev.ucp.shopping.checkout": [
              {
                version: "2026-01-23",
                spec: "https://ucp.dev/specification/checkout",
                schema: "https://ucp.dev/2026-01-23/schemas/shopping/checkout.json",
                config: {
                  supported_currencies: ["EUR"],
                  idempotency_key_required: false
                }
              }
            ],
            "dev.ucp.shopping.fulfillment": [
              {
                version: "2026-01-23",
                spec: "https://ucp.dev/specification/fulfillment",
                schema: "https://ucp.dev/2026-01-23/schemas/shopping/fulfillment.json",
                extends: "dev.ucp.shopping.discount"
              }
            ],
            "dev.ucp.shopping.discount": [
              {
                version: "2026-01-23",
                spec: "https://ucp.dev/specification/discount",
                schema: "https://ucp.dev/2026-01-23/schemas/shopping/discount.json",
                extends: "dev.ucp.shopping.fulfillment"
              }
            ],
            "dev.ucp.shopping.custom_vip": [
              {
                version: "2026-01-23",
                spec: "https://atelier-verre.eu/ucp/vip",
                schema: "https://atelier-verre.eu/ucp/vip.json"
              }
            ]
          },
          payment_handlers: {
            "com.stripe.pay": [
              {
                id: "8c9202bd-63cc-4241-8d24-d57ce69ea31c",
                version: "2026-01-23",
                spec: "https://docs.stripe.com/agentic-commerce/ucp/2026-01-23",
                schema: "http://127.0.0.1:9001/stripe-config.json"
              }
            ]
          }
        }
      },
      agent_card: {
        name: "Atelier Verre Internal Agent",
        url: "http://localhost:9000/a2a",
        version: "0.1.0",
        skills: []
      },
      schema_org_offers: [
        {
          name: "Hand-Blown Carafe 750ml",
          sku: "AV-CARAFE-750",
          price: "86.00",
          priceCurrency: "EUR",
          availability: "https://schema.org/InStock"
        }
      ]
    },
    "production-google-stripe-ucp": {
      domain: "nordic-roast.shop",
      platform: "shopify",
      status_code: 200,
      http_headers: prodBundle.http_headers,
      manifest: prodBundle.manifest,
      agent_card: prodBundle.agent_card,
      llms_txt: "# Nordic Roast Coffee\n> Specialty coffee roaster supporting UCP 2026-01-23 & AP2 mandates.\n",
      schema_org_offers: [
        {
          name: "Nordic Roast Flagship Single Origin 250g",
          sku: "UCP-SKU-101",
          price: "34.00",
          priceCurrency: "USD",
          availability: "https://schema.org/InStock"
        }
      ]
    }
  };
}
