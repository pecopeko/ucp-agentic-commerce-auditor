"""1-Click Universal Commerce Protocol (`/.well-known/ucp`) & A2A Manifest Generator.

Generates spec-compliant `ucp.dev` (`2026-01-23`) discovery profiles, companion A2A
(`/.well-known/agent.json`) Agent Cards, Schema.org `Product`/`Offer` JSON-LD snippets,
and production edge routing configs (Cloudflare Worker + Nginx) with deterministic
RFC 4122 UUIDv5 payment handler identifiers.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlparse
import uuid

DEFAULT_UCP_VERSION = "2026-01-23"
MCP_STATELESS_REVISION = "2026-07-28"

ISO_4217_CURRENCIES: frozenset[str] = frozenset(
    {
        "USD",
        "JPY",
        "EUR",
        "GBP",
        "CAD",
        "AUD",
        "NZD",
        "CHF",
        "SGD",
        "HKD",
        "KRW",
        "TWD",
        "SEK",
        "NOK",
        "DKK",
        "PLN",
        "CZK",
        "BRL",
        "MXN",
        "INR",
        "THB",
        "MYR",
        "IDR",
        "PHP",
        "VND",
        "ZAR",
        "AED",
        "SAR",
        "ILS",
        "TRY",
        "CNY",
    }
)

CANONICAL_CAPABILITY_ALIASES: dict[str, str] = {
    "checkout": "dev.ucp.shopping.checkout",
    "dev.ucp.shopping.checkout": "dev.ucp.shopping.checkout",
    "fulfillment": "dev.ucp.shopping.fulfillment",
    "dev.ucp.shopping.fulfillment": "dev.ucp.shopping.fulfillment",
    "discount": "dev.ucp.shopping.discount",
    "dev.ucp.shopping.discount": "dev.ucp.shopping.discount",
    "order": "dev.ucp.shopping.order",
    "dev.ucp.shopping.order": "dev.ucp.shopping.order",
    "ap2_mandate": "dev.ucp.shopping.ap2_mandate",
    "dev.ucp.shopping.ap2_mandate": "dev.ucp.shopping.ap2_mandate",
    "identity_linking": "dev.ucp.identity_linking",
    "dev.ucp.identity_linking": "dev.ucp.identity_linking",
}

DEFAULT_ENABLED_CAPABILITIES: tuple[str, ...] = (
    "dev.ucp.shopping.checkout",
    "dev.ucp.shopping.fulfillment",
    "dev.ucp.shopping.discount",
    "dev.ucp.shopping.order",
    "dev.ucp.shopping.ap2_mandate",
)

DEFAULT_PAYMENT_HANDLERS: tuple[str, ...] = (
    "com.google.pay",
    "com.stripe.pay",
)

PAYMENT_HANDLER_ALIASES: dict[str, str] = {
    "google_pay": "com.google.pay",
    "com.google.pay": "com.google.pay",
    "stripe": "com.stripe.pay",
    "com.stripe.pay": "com.stripe.pay",
    "com.stripe.payments": "com.stripe.payments",
    "shop_pay": "shop.pay",
    "shop.pay": "shop.pay",
    "dev.shopify.shop_pay": "dev.shopify.shop_pay",
}

_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DATE_VERSION_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_FORBIDDEN_DOMAIN_SUFFIXES = (".local", ".internal", ".localhost", ".home.arpa")
_FORBIDDEN_EXACT_DOMAINS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata.google.internal",
        "metadata.goog",
        "metadata",
    }
)


def deterministic_handler_uuid(
    domain: str,
    handler_key: str,
    version: str = DEFAULT_UCP_VERSION,
) -> str:
    """Compute deterministic RFC 4122 UUIDv5 for a merchant's UCP payment handler."""
    norm_domain = str(domain or "").strip().lower().rstrip(".")
    norm_handler = str(handler_key or "").strip().lower()
    norm_version = str(version or DEFAULT_UCP_VERSION).strip()
    seed_uri = f"https://{norm_domain}/.well-known/ucp?version={norm_version}#{norm_handler}"
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed_uri))


def normalize_store_domain(raw_domain: str) -> str:
    """Normalize and validate a public merchant domain name."""
    raw = str(raw_domain or "").strip()
    if not raw:
        raise ValueError("Store domain is required.")

    if "://" in raw:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").strip().lower().rstrip(".")
    else:
        host = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].strip().lower().rstrip(".")
        if ":" in host:
            host = host.split(":", 1)[0]

    if not host:
        raise ValueError(f"Could not extract hostname from {raw_domain!r}.")

    if host in _FORBIDDEN_EXACT_DOMAINS or any(host.endswith(sfx) for sfx in _FORBIDDEN_DOMAIN_SUFFIXES):
        raise ValueError(f"Reserved or local hostname is disallowed for UCP merchant discovery: {host}")

    try:
        ipaddress.ip_address(host)
        raise ValueError(f"IP literal {host} is disallowed; provide a public DNS domain.")
    except ValueError as exc:
        if "disallowed" in str(exc):
            raise

    labels = host.split(".")
    if len(labels) < 2 or len(labels[-1]) < 2 or not labels[-1].isalpha():
        raise ValueError(f"Invalid public store domain syntax: {host}")

    for label in labels:
        if not _DOMAIN_LABEL_RE.match(label):
            raise ValueError(f"Invalid DNS label {label!r} in domain {host}.")

    return host


def normalize_platform(raw_platform: str) -> str:
    """Normalize store platform identifier to shopify, custom_rest, or stateless_mcp."""
    val = str(raw_platform or "shopify").strip().lower().replace("-", "_").replace(" ", "_")
    if val in ("shopify", "shopify_plus"):
        return "shopify"
    if val in ("custom_rest", "rest", "openapi", "custom"):
        return "custom_rest"
    if val in ("stateless_mcp", "mcp", "mcp_streamable_http"):
        return "stateless_mcp"
    raise ValueError(
        f"Unsupported platform {raw_platform!r}; expected 'Shopify', 'Custom REST', or 'Stateless MCP'."
    )


def _human_store_title(domain: str, store_name: str | None = None) -> str:
    if store_name and str(store_name).strip():
        return str(store_name).strip()
    stem = domain.split(".", 1)[0]
    words = [part.capitalize() for part in re.split(r"[-_]+", stem) if part]
    return " ".join(words) if words else domain


def _normalize_capabilities_list(capabilities: list[str] | tuple[str, ...] | None) -> list[str]:
    raw_items = list(capabilities) if capabilities is not None else list(DEFAULT_ENABLED_CAPABILITIES)
    resolved: list[str] = []
    for item in raw_items:
        key = str(item or "").strip().lower()
        if not key:
            continue
        mapped = CANONICAL_CAPABILITY_ALIASES.get(key, key)
        if mapped not in resolved:
            resolved.append(mapped)

    # Ensure core checkout is present whenever capabilities are empty or extensions depend on it
    needs_checkout = (
        not resolved
        or "dev.ucp.shopping.fulfillment" in resolved
        or "dev.ucp.shopping.discount" in resolved
        or "dev.ucp.shopping.ap2_mandate" in resolved
    )
    if needs_checkout and "dev.ucp.shopping.checkout" not in resolved:
        resolved.insert(0, "dev.ucp.shopping.checkout")
    elif "dev.ucp.shopping.checkout" in resolved:
        resolved.remove("dev.ucp.shopping.checkout")
        resolved.insert(0, "dev.ucp.shopping.checkout")

    return resolved


def _normalize_payment_handlers_list(handlers: list[str] | tuple[str, ...] | None) -> list[str]:
    raw_items = list(handlers) if handlers is not None else list(DEFAULT_PAYMENT_HANDLERS)
    resolved: list[str] = []
    for item in raw_items:
        key = str(item or "").strip().lower()
        if not key:
            continue
        mapped = PAYMENT_HANDLER_ALIASES.get(key, key)
        if mapped not in resolved:
            resolved.append(mapped)
    if not resolved:
        resolved.append("com.google.pay")
    return resolved


def _normalize_currencies_list(currencies: list[str] | tuple[str, ...] | None) -> list[str]:
    raw_items = list(currencies) if currencies is not None else ["USD"]
    resolved: list[str] = []
    for item in raw_items:
        code = str(item or "").strip().upper()
        if not code:
            continue
        if code not in ISO_4217_CURRENCIES:
            raise ValueError(f"Unsupported or non-ISO-4217 currency code: {code!r}")
        if code not in resolved:
            resolved.append(code)
    return resolved or ["USD"]


def _build_payment_handler_entry(domain: str, handler_key: str, version: str) -> dict[str, Any]:
    handler_id = deterministic_handler_uuid(domain, handler_key, version)
    if handler_key == "com.google.pay":
        return {
            "id": handler_id,
            "version": version,
            "spec": f"https://pay.google.com/gp/p/ucp/{version}/",
            "schema": f"https://pay.google.com/gp/p/ucp/{version}/schemas/config.json",
            "config_schema": f"https://pay.google.com/gp/p/ucp/{version}/schemas/config.json",
            "instrument_schemas": [
                f"https://pay.google.com/gp/p/ucp/{version}/schemas/card_payment_instrument.json"
            ],
            "config": {
                "environment": "PRODUCTION",
                "ap2_mandate_verification": True,
            },
        }
    if handler_key in ("com.stripe.pay", "com.stripe.payments"):
        return {
            "id": handler_id,
            "version": version,
            "spec": f"https://docs.stripe.com/agentic-commerce/ucp/{version}",
            "schema": f"https://ucp.stripe.com/{version}/schemas/config.json",
            "config_schema": f"https://ucp.stripe.com/{version}/schemas/config.json",
            "instrument_schemas": [
                f"https://ucp.stripe.com/{version}/schemas/shared_payment_token.json"
            ],
            "config": {
                "network_tokenization": True,
                "ap2_mandate_verification": True,
            },
        }
    if handler_key in ("shop.pay", "dev.shopify.shop_pay"):
        return {
            "id": handler_id,
            "version": version,
            "spec": "https://shopify.dev/docs/agents/ucp/shop-pay",
            "schema": f"https://shopify.dev/ucp/{version}/schemas/shop_pay_config.json",
            "config_schema": f"https://shopify.dev/ucp/{version}/schemas/shop_pay_config.json",
            "instrument_schemas": [
                f"https://shopify.dev/ucp/{version}/schemas/shop_pay_instrument.json"
            ],
            "config": {
                "express_wallet": True,
                "ap2_mandate_verification": True,
            },
        }
    return {
        "id": handler_id,
        "version": version,
        "spec": f"https://{domain}/ucp/specs/payments/{handler_key}",
        "schema": f"https://{domain}/ucp/{version}/schemas/payments/{handler_key}.json",
        "config_schema": f"https://{domain}/ucp/{version}/schemas/payments/{handler_key}.json",
        "instrument_schemas": [
            f"https://{domain}/ucp/{version}/schemas/payments/{handler_key}_instrument.json"
        ],
        "config": {
            "ap2_mandate_verification": True,
        },
    }


def _build_services_block(domain: str, platform: str, version: str) -> dict[str, list[dict[str, Any]]]:
    if platform == "shopify":
        return {
            "dev.ucp.shopping": [
                {
                    "version": version,
                    "spec": "https://ucp.dev/specification/overview",
                    "transport": "rest",
                    "endpoint": f"https://{domain}/api/ucp/{version}",
                    "schema": f"https://ucp.dev/{version}/services/shopping/openapi.json",
                },
                {
                    "version": version,
                    "spec": "https://ucp.dev/specification/mcp",
                    "transport": "mcp",
                    "endpoint": f"https://{domain}/api/ucp/mcp",
                    "schema": f"https://ucp.dev/{version}/services/shopping/openrpc.json",
                    "config": {
                        "mcp_protocol_version": MCP_STATELESS_REVISION,
                        "stateless_streamable_http": True,
                        "required_meta": ["ucp-agent", "idempotency-key"],
                    },
                },
            ]
        }
    if platform == "stateless_mcp":
        return {
            "dev.ucp.shopping": [
                {
                    "version": version,
                    "spec": "https://ucp.dev/specification/mcp",
                    "transport": "mcp",
                    "endpoint": f"https://{domain}/ucp/mcp",
                    "schema": f"https://ucp.dev/{version}/services/shopping/openrpc.json",
                    "config": {
                        "mcp_protocol_version": MCP_STATELESS_REVISION,
                        "stateless_streamable_http": True,
                        "required_meta": ["ucp-agent", "idempotency-key"],
                    },
                },
                {
                    "version": version,
                    "spec": "https://ucp.dev/specification/overview",
                    "transport": "rest",
                    "endpoint": f"https://{domain}/ucp/v1",
                    "schema": f"https://ucp.dev/{version}/services/shopping/openapi.json",
                },
            ]
        }
    return {
        "dev.ucp.shopping": [
            {
                "version": version,
                "spec": "https://ucp.dev/specification/overview",
                "transport": "rest",
                "endpoint": f"https://{domain}/ucp/v1",
                "schema": f"https://ucp.dev/{version}/services/shopping/openapi.json",
            }
        ]
    }


def _build_capabilities_block(
    domain: str,
    capability_keys: list[str],
    currencies: list[str],
    version: str,
) -> dict[str, list[dict[str, Any]]]:
    has_ap2 = "dev.ucp.shopping.ap2_mandate" in capability_keys
    caps: dict[str, list[dict[str, Any]]] = {}
    for key in capability_keys:
        if key == "dev.ucp.shopping.checkout":
            caps[key] = [
                {
                    "version": version,
                    "spec": "https://ucp.dev/specification/checkout",
                    "schema": f"https://ucp.dev/{version}/schemas/shopping/checkout.json",
                    "config": {
                        "supported_currencies": list(currencies),
                        "seller_of_record": domain,
                        "idempotency_key_required": True,
                        "idempotency_ttl_seconds": 86400,
                        "ap2_mandate_required": True,
                    },
                }
            ]
        elif key == "dev.ucp.shopping.fulfillment":
            caps[key] = [
                {
                    "version": version,
                    "spec": "https://ucp.dev/specification/fulfillment",
                    "schema": f"https://ucp.dev/{version}/schemas/shopping/fulfillment.json",
                    "extends": "dev.ucp.shopping.checkout",
                }
            ]
        elif key == "dev.ucp.shopping.discount":
            caps[key] = [
                {
                    "version": version,
                    "spec": "https://ucp.dev/specification/discount",
                    "schema": f"https://ucp.dev/{version}/schemas/shopping/discount.json",
                    "extends": "dev.ucp.shopping.checkout",
                }
            ]
        elif key == "dev.ucp.shopping.order":
            caps[key] = [
                {
                    "version": version,
                    "spec": "https://ucp.dev/specification/order",
                    "schema": f"https://ucp.dev/{version}/schemas/shopping/order.json",
                }
            ]
        elif key == "dev.ucp.shopping.ap2_mandate":
            caps[key] = [
                {
                    "version": version,
                    "spec": "https://ucp.dev/specification/ap2-mandate",
                    "schema": f"https://ucp.dev/{version}/schemas/shopping/ap2_mandate.json",
                    "extends": "dev.ucp.shopping.checkout",
                    "config": {
                        "mandate_formats": ["CheckoutMandate", "SD-JWT-VC"],
                        "require_user_signature": True,
                        "replay_nonce_ttl_seconds": 300,
                    },
                }
            ]
        elif key == "dev.ucp.identity_linking":
            caps[key] = [
                {
                    "version": version,
                    "spec": "https://ucp.dev/specification/identity-linking",
                    "schema": f"https://ucp.dev/{version}/schemas/identity_linking.json",
                }
            ]
        else:
            slug = key.split(".")[-1]
            entry: dict[str, Any] = {
                "version": version,
                "spec": f"https://{domain}/ucp/specs/{slug}",
                "schema": f"https://{domain}/ucp/{version}/schemas/{slug}.json",
            }
            if "dev.ucp.shopping.checkout" in capability_keys:
                entry["extends"] = "dev.ucp.shopping.checkout"
            caps[key] = [entry]

    if not has_ap2 and "dev.ucp.shopping.checkout" in caps:
        caps["dev.ucp.shopping.checkout"][0]["config"]["ap2_mandate_required"] = True

    return caps


def build_a2a_agent_card(
    domain: str,
    *,
    platform: str = "shopify",
    capability_keys: list[str] | None = None,
    version: str = DEFAULT_UCP_VERSION,
    store_name: str | None = None,
) -> dict[str, Any]:
    """Build a companion A2A (`/.well-known/agent.json`) Agent Card aligned with UCP."""
    title = _human_store_title(domain, store_name)
    caps = capability_keys if capability_keys is not None else list(DEFAULT_ENABLED_CAPABILITIES)
    endpoint_path = "/api/ucp/a2a" if platform == "shopify" else "/ucp/a2a"

    skills: list[dict[str, Any]] = [
        {
            "id": "ucp-shopping-checkout",
            "name": f"{title} UCP Native Checkout",
            "description": "Negotiates cart pricing, taxes, and AP2 payment mandates via Universal Commerce Protocol.",
            "tags": ["commerce", "ucp", "checkout", "ap2"],
        }
    ]
    if "dev.ucp.shopping.fulfillment" in caps:
        skills.append(
            {
                "id": "ucp-shopping-fulfillment",
                "name": "Fulfillment & Shipping Options",
                "description": "Calculates real-time carrier rates, delivery windows, and pickup availability.",
                "tags": ["commerce", "ucp", "fulfillment"],
            }
        )
    if "dev.ucp.shopping.order" in caps:
        skills.append(
            {
                "id": "ucp-shopping-order",
                "name": "Post-Purchase Order Lifecycle",
                "description": "Queries verified order shipment tracking, receipts, and return eligibility.",
                "tags": ["commerce", "ucp", "orders"],
            }
        )

    return {
        "name": f"{title} Commerce Agent",
        "description": f"Official UCP ({version}) and AP2 mandate-verified commerce endpoint for {domain}.",
        "url": f"https://{domain}{endpoint_path}",
        "version": "1.0.0",
        "protocolVersion": "0.3.0",
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": True,
        },
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": skills,
    }


def build_cloudflare_worker_snippet(
    manifest: dict[str, Any],
    agent_card: dict[str, Any] | None = None,
) -> str:
    """Generate a zero-dependency Cloudflare Worker ES Module serving /.well-known/ucp."""
    manifest_json = json.dumps(manifest, indent=2)
    agent_json = json.dumps(agent_card, indent=2) if agent_card is not None else "null"
    lines = [
        "// Cloudflare Worker Edge Route: https://<your-domain>/.well-known/*",
        "const UCP_MANIFEST = " + manifest_json + ";",
        "const A2A_AGENT_CARD = " + agent_json + ";",
        "",
        "const EDGE_HEADERS = {",
        '  "Content-Type": "application/json; charset=utf-8",',
        '  "Access-Control-Allow-Origin": "*",',
        '  "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",',
        '  "Access-Control-Allow-Headers": "Content-Type, Accept, Idempotency-Key, UCP-Agent",',
        '  "Access-Control-Expose-Headers": "Content-Type, Cache-Control, ETag",',
        '  "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400",',
        '  "X-Content-Type-Options": "nosniff",',
        "};",
        "",
        "export default {",
        "  async fetch(request) {",
        "    const url = new URL(request.url);",
        '    if (request.method === "OPTIONS") {',
        "      return new Response(null, { status: 204, headers: EDGE_HEADERS });",
        "    }",
        '    if (request.method !== "GET" && request.method !== "HEAD") {',
        '      return new Response(JSON.stringify({ error: "method_not_allowed" }), {',
        "        status: 405,",
        "        headers: EDGE_HEADERS,",
        "      });",
        "    }",
        '    if (url.pathname === "/.well-known/ucp") {',
        "      const body = JSON.stringify(UCP_MANIFEST, null, 2);",
        '      return new Response(request.method === "HEAD" ? null : body, {',
        "        status: 200,",
        "        headers: EDGE_HEADERS,",
        "      });",
        "    }",
        '    if (A2A_AGENT_CARD && (url.pathname === "/.well-known/agent.json" || url.pathname === "/.well-known/agent-card.json")) {',
        "      const body = JSON.stringify(A2A_AGENT_CARD, null, 2);",
        '      return new Response(request.method === "HEAD" ? null : body, {',
        "        status: 200,",
        "        headers: EDGE_HEADERS,",
        "      });",
        "    }",
        '    return new Response(JSON.stringify({ error: "not_found" }), { status: 404, headers: EDGE_HEADERS });',
        "  },",
        "};",
    ]
    return "\n".join(lines) + "\n"


def build_nginx_snippet(domain: str) -> str:
    """Generate an Nginx server location snippet for /.well-known/ucp and /.well-known/agent.json."""
    lines = [
        f"# Nginx TLS edge configuration for {domain}",
        "location = /.well-known/ucp {",
        "    default_type application/json;",
        "    charset utf-8;",
        '    add_header Access-Control-Allow-Origin "*" always;',
        '    add_header Access-Control-Allow-Methods "GET, HEAD, OPTIONS" always;',
        '    add_header Access-Control-Allow-Headers "Content-Type, Accept, Idempotency-Key, UCP-Agent" always;',
        '    add_header Access-Control-Expose-Headers "Content-Type, Cache-Control, ETag" always;',
        '    add_header Cache-Control "public, max-age=3600, stale-while-revalidate=86400" always;',
        '    add_header X-Content-Type-Options "nosniff" always;',
        "    if ($request_method = OPTIONS) {",
        "        return 204;",
        "    }",
        "    try_files /.well-known/ucp.json =404;",
        "}",
        "",
        "location = /.well-known/agent.json {",
        "    default_type application/json;",
        "    charset utf-8;",
        '    add_header Access-Control-Allow-Origin "*" always;',
        '    add_header Cache-Control "public, max-age=3600, stale-while-revalidate=86400" always;',
        '    add_header X-Content-Type-Options "nosniff" always;',
        "    try_files /.well-known/agent.json =404;",
        "}",
    ]
    return "\n".join(lines) + "\n"


def generate_ucp_bundle(
    domain: str,
    *,
    platform: str = "shopify",
    capabilities: list[str] | tuple[str, ...] | None = None,
    payment_handlers: list[str] | tuple[str, ...] | None = None,
    currencies: list[str] | tuple[str, ...] | None = None,
    version: str = DEFAULT_UCP_VERSION,
    include_a2a_agent_card: bool = True,
    store_name: str | None = None,
) -> dict[str, Any]:
    """Generate a complete 100/100 UCP (`/.well-known/ucp`) + edge deployment bundle."""
    norm_domain = normalize_store_domain(domain)
    norm_platform = normalize_platform(platform)
    norm_version = str(version or DEFAULT_UCP_VERSION).strip()
    if not _DATE_VERSION_RE.match(norm_version):
        raise ValueError(f"UCP version must match YYYY-MM-DD (got {version!r}).")

    cap_keys = _normalize_capabilities_list(capabilities)
    handler_keys = _normalize_payment_handlers_list(payment_handlers)
    norm_currencies = _normalize_currencies_list(currencies)

    services_block = _build_services_block(norm_domain, norm_platform, norm_version)
    capabilities_block = _build_capabilities_block(norm_domain, cap_keys, norm_currencies, norm_version)
    handlers_block: dict[str, list[dict[str, Any]]] = {
        h_key: [_build_payment_handler_entry(norm_domain, h_key, norm_version)]
        for h_key in handler_keys
    }

    manifest: dict[str, Any] = {
        "ucp": {
            "version": norm_version,
            "services": services_block,
            "capabilities": capabilities_block,
            "payment_handlers": handlers_block,
        }
    }

    agent_card = (
        build_a2a_agent_card(
            norm_domain,
            platform=norm_platform,
            capability_keys=cap_keys,
            version=norm_version,
            store_name=store_name,
        )
        if include_a2a_agent_card
        else None
    )

    http_headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
        "Access-Control-Expose-Headers": "Content-Type, Cache-Control, ETag",
        "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400",
        "X-Content-Type-Options": "nosniff",
    }

    primary_currency = norm_currencies[0]
    default_price = "4800" if primary_currency == "JPY" else "34.00"
    title = _human_store_title(norm_domain, store_name)
    schema_org_product_jsonld = {
        "@context": "https://schema.org",
        "@type": "Product",
        "name": f"{title} Flagship SKU",
        "sku": "UCP-SKU-101",
        "offers": {
            "@type": "Offer",
            "url": f"https://{norm_domain}/products/ucp-sku-101",
            "priceCurrency": primary_currency,
            "price": default_price,
            "availability": "https://schema.org/InStock",
            "seller": {
                "@type": "Organization",
                "name": title,
            },
        },
    }

    return {
        "domain": norm_domain,
        "platform": norm_platform,
        "version": norm_version,
        "enabled_capabilities": cap_keys,
        "enabled_payment_handlers": handler_keys,
        "supported_currencies": norm_currencies,
        "manifest": manifest,
        "agent_card": agent_card,
        "http_headers": http_headers,
        "schema_org_product_jsonld": schema_org_product_jsonld,
        "cloudflare_worker_js": build_cloudflare_worker_snippet(manifest, agent_card),
        "nginx_conf": build_nginx_snippet(norm_domain),
    }
