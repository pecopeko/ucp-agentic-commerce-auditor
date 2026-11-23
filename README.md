# UCPGATE · Universal Commerce Protocol (`/.well-known/ucp`), AP2 & A2A Readiness Auditor

Live browser-local workbench (`connect-src 'none'`): **<https://pecopeko.github.io/ucp-agentic-commerce-auditor/>**

Audits merchant agentic commerce manifests against official `ucp.dev` (`2026-01-23`) specifications across 10 concrete gates:

1. **`UCP-01`** · Envelope & Date-Stamped Protocol Version (`ucp.version` `YYYY-MM-DD`, e.g. `2026-01-23`)
2. **`UCP-02`** · Reverse-Domain Namespace Grammar (`{tld}.{domain}.{service}.{capability}`) & Squatting Guard
3. **`UCP-03`** · `services` Transports (`rest` / `mcp`), HTTPS-Only Endpoints & SSRF / Private-IP Rejection
4. **`UCP-04`** · Core `dev.ucp.shopping.checkout` Completeness & Spec/Schema Version Alignment
5. **`UCP-05`** · Capability Composition DAG (`extends` Reference Resolution & Cycle Detection)
6. **`UCP-06`** · `payment_handlers` (`com.google.pay`, `com.stripe.pay`, `shop.pay`) UUIDv5, HTTPS Schemas & Secret Leak Guard
7. **`UCP-07`** · Stateless MCP (`2026-07-28`) / OpenAPI & A2A (`/.well-known/agent.json`) Dual-Surface Parity
8. **`UCP-08`** · Price, Currency & Inventory Hallucination Guard (`Schema.org Offer` vs UCP Checkout Parity)
9. **`UCP-09`** · AP2 Cryptographic Payment Mandate & `Idempotency-Key` Replay Protection
10. **`UCP-10`** · Edge Delivery Headers (`application/json`, CORS, `Cache-Control`) & **1-Click Cloudflare Worker / Nginx Builder**

## Multi-Store Batch Auditing & Data APIs

- **Shopify Public Catalog Feed Extractor (`$1 / 1,000 products`)**: <https://apify.com/pecopeko/shopify-public-catalog-feed-extractor>
- **Website Tech Stack & Sitemap Extractor (`$2 / 1,000 sites`)**: <https://apify.com/pecopeko/website-tech-stack-sitemap-extractor>
- **Zenn Engineering Book (`¥1,200`)**: <https://zenn.dev/pecopeko/books/afml-quant-and-local-ai-guard>
- **BOOTH Offline Back-Office Automation Pro Kit (`¥1,980`)**: <https://pecopeko1011.booth.pm/items/9179705>

## Run Tests

```bash
npm test
```

Apache-2.0 · Crafted by peco (`pecopeko`)
