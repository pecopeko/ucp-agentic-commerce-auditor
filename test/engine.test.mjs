import assert from "node:assert/strict";
import test from "node:test";

import {
  GATE_DEFINITIONS,
  UcpParseError,
  auditUcpReadiness,
  auditUcpText,
  buildSamplePresets,
  deterministicHandlerUuid,
  extractSchemaOrgOffersFromHtml,
  generateUcpBundle,
  inspectCapabilityDag,
  inspectHttpsPublicUrl,
  stripJsoncComments
} from "../engine.js";

test("GATE_DEFINITIONS defines 10 gates summing to 100 points", () => {
  assert.equal(GATE_DEFINITIONS.length, 10);
  const total = GATE_DEFINITIONS.reduce((acc, g) => acc + g.weight, 0);
  assert.equal(total, 100);
});

test("deterministicHandlerUuid generates valid RFC 4122 UUIDv5 deterministically", () => {
  const id1 = deterministicHandlerUuid("nordic-roast.shop", "com.google.pay", "2026-01-23");
  const id2 = deterministicHandlerUuid("nordic-roast.shop", "com.google.pay", "2026-01-23");
  const idStripe = deterministicHandlerUuid("nordic-roast.shop", "com.stripe.pay", "2026-01-23");
  assert.equal(id1, id2);
  assert.notEqual(id1, idStripe);
  assert.match(id1, /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});

test("presets evaluate with expected scores and findings", () => {
  const presets = buildSamplePresets();
  const prod = auditUcpReadiness(presets["production-google-stripe-ucp"]);
  assert.equal(prod.score, 100);
  assert.equal(prod.grade, "A");
  assert.equal(prod.status, "compliant");
  assert.equal(prod.gates_passed, 10);
  assert.equal(prod.gates_failed, 0);

  const broken = auditUcpReadiness(presets["broken-shopify-draft"]);
  assert.equal(broken.status, "non_compliant");
  assert.ok(broken.score < 40);
  const brokenCodes = broken.gates.flatMap((g) => g.findings.map((f) => f.code));
  assert.ok(brokenCodes.includes("INVALID_UCP_VERSION_FORMAT"));
  assert.ok(brokenCodes.includes("DANGLING_EXTENDS_PARENT"));
  assert.ok(brokenCodes.includes("LEAKED_PSP_SECRET_IN_MANIFEST"));
  assert.ok(brokenCodes.includes("OFFER_UCP_CURRENCY_MISMATCH"));
  assert.ok(brokenCodes.includes("INVALID_DISCOVERY_CONTENT_TYPE"));

  const cyclic = auditUcpReadiness(presets["cyclic-http-ssrf"]);
  assert.equal(cyclic.status, "non_compliant");
  assert.equal(cyclic.dag.is_acyclic, false);
  const cyclicCodes = cyclic.gates.flatMap((g) => g.findings.map((f) => f.code));
  assert.ok(cyclicCodes.includes("CAPABILITY_EXTENDS_CYCLE"));
  assert.ok(cyclicCodes.includes("ENDPOINT_SSRF_PRIVATE_IP"));
  assert.ok(cyclicCodes.includes("ENDPOINT_CLEARTEXT_HTTP_URL"));
  assert.ok(cyclicCodes.includes("DEPRECATED_MCP_SSE_TRANSPORT"));
  assert.ok(cyclicCodes.includes("IDEMPOTENCY_PROTECTION_DISABLED"));
});

test("generator round-trip produces 100/100 across Shopify, Custom REST, and Stateless MCP", () => {
  for (const platform of ["shopify", "custom_rest", "stateless_mcp"]) {
    const bundle = generateUcpBundle("solstice-gear.store", {
      platform,
      paymentHandlers: ["com.google.pay", "com.stripe.pay", "shop.pay"],
      currencies: ["USD", "JPY"]
    });
    const rep = auditUcpReadiness({
      domain: bundle.domain,
      platform: bundle.platform,
      status_code: 200,
      http_headers: bundle.http_headers,
      manifest: bundle.manifest,
      agent_card: bundle.agent_card,
      schema_org_offers: [bundle.schema_org_product_jsonld.offers]
    });
    assert.equal(rep.score, 100, `Expected 100 for platform ${platform}`);
    assert.equal(rep.status, "compliant");
    assert.ok(bundle.cloudflare_worker_js.includes("Access-Control-Allow-Origin"));
    assert.ok(bundle.nginx_conf.includes("location = /.well-known/ucp"));
  }
});

test("inspectHttpsPublicUrl blocks SSRF private IPs, localhost, and cleartext HTTP", () => {
  for (const bad of [
    "http://nordic-roast.shop/ucp",
    "https://localhost/ucp",
    "https://127.0.0.1/ucp",
    "https://10.0.0.8/ucp",
    "https://169.254.169.254/latest/meta-data",
    "https://192.168.1.20/ucp",
    "https://100.64.10.2/ucp",
    "https://[::1]/ucp",
    "https://metadata.google.internal/computeMetadata/v1/"
  ]) {
    const res = inspectHttpsPublicUrl(bad);
    assert.equal(res.ok, false, `Expected ${bad} to be rejected`);
  }
  assert.equal(inspectHttpsPublicUrl("https://nordic-roast.shop/api/ucp/2026-01-23").ok, true);
});

test("inspectCapabilityDag detects 3-node cycles and self-loops", () => {
  const selfDag = inspectCapabilityDag({
    "dev.ucp.shopping.checkout": [{ extends: "dev.ucp.shopping.checkout" }]
  });
  assert.equal(selfDag.is_acyclic, false);

  const ring3 = inspectCapabilityDag({
    "shop.brand.shopping.a": [{ extends: "shop.brand.shopping.b" }],
    "shop.brand.shopping.b": [{ extends: "shop.brand.shopping.c" }],
    "shop.brand.shopping.c": [{ extends: "shop.brand.shopping.a" }]
  });
  assert.equal(ring3.is_acyclic, false);
  assert.equal(ring3.cycles.length, 1);
});

test("JSONC comments and HTML Schema.org JSON-LD extraction work cleanly", () => {
  const rawJsonc = `
    // Leading comment
    {
      "ucp": {
        /* block comment */
        "version": "2026-01-23",
        "services": {},
        "capabilities": {}
      }
    }
  `;
  const stripped = stripJsoncComments(rawJsonc);
  assert.doesNotThrow(() => JSON.parse(stripped));
  const rep = auditUcpText(rawJsonc);
  assert.equal(rep.ucp_version, "2026-01-23");

  const html = `<!doctype html><html><head><script type="application/ld+json">
    {"@context":"https://schema.org","@type":"Product","name":"Pour Over Kettle","sku":"PK-1","offers":{"@type":"Offer","price":"68.00","priceCurrency":"USD","availability":"https://schema.org/InStock"}}
  </script></head><body></body></html>`;
  const offers = extractSchemaOrgOffersFromHtml(html);
  assert.equal(offers.length, 1);
  assert.equal(offers[0].price_currency, "USD");
  assert.equal(offers[0].price, "68.00");

  assert.throws(() => auditUcpText("{broken"), UcpParseError);
});
