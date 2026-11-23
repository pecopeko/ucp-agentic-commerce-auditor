"""10-Gate Universal Commerce Protocol (`/.well-known/ucp`), AP2 & A2A Readiness Auditor.

Verifies merchant agentic commerce manifests against official `ucp.dev` (`2026-01-23`)
specifications, Stateless MCP (`2026-07-28`) / OpenAPI dual-surface rules, A2A Agent Cards
(`/.well-known/agent.json`), Schema.org `Product`/`Offer` price-currency parity, and AP2
cryptographic payment mandate / idempotency protections.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import datetime as dt
import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlparse

from .generator import (
    DEFAULT_UCP_VERSION,
    ISO_4217_CURRENCIES,
    MCP_STATELESS_REVISION,
    generate_ucp_bundle,
    normalize_store_domain,
)

GATE_DEFINITIONS: tuple[dict[str, Any], ...] = (
    {
        "gate_number": 1,
        "gate_id": "UCP-01",
        "weight": 10,
        "title": "Envelope & Date-Stamped Protocol Version (ucp.version)",
        "spec_ref": "ucp.dev/specification/overview#profile-version",
    },
    {
        "gate_number": 2,
        "gate_id": "UCP-02",
        "weight": 10,
        "title": "Reverse-Domain Namespace Syntax & Collision Safety",
        "spec_ref": "ucp.dev/specification/overview#namespaces",
    },
    {
        "gate_number": 3,
        "gate_id": "UCP-03",
        "weight": 10,
        "title": "Service Transports, HTTPS-Only Endpoints & SSRF Guard",
        "spec_ref": "ucp.dev/specification/overview#services",
    },
    {
        "gate_number": 4,
        "gate_id": "UCP-04",
        "weight": 10,
        "title": "Core dev.ucp.shopping.checkout Completeness & Schema Alignment",
        "spec_ref": "ucp.dev/specification/checkout",
    },
    {
        "gate_number": 5,
        "gate_id": "UCP-05",
        "weight": 10,
        "title": "Capability Composition DAG (extends Resolution & Cycle Check)",
        "spec_ref": "ucp.dev/specification/overview#capability-extensions",
    },
    {
        "gate_number": 6,
        "gate_id": "UCP-06",
        "weight": 10,
        "title": "Payment Handlers (Google Pay / Stripe / Shop Pay) UUID & HTTPS Schemas",
        "spec_ref": "ucp.dev/specification/payments",
    },
    {
        "gate_number": 7,
        "gate_id": "UCP-07",
        "weight": 10,
        "title": "Stateless MCP (2026-07-28) / OpenAPI & A2A Dual-Surface Parity",
        "spec_ref": "ucp.dev/specification/mcp",
    },
    {
        "gate_number": 8,
        "gate_id": "UCP-08",
        "weight": 10,
        "title": "Price, Currency & Inventory Hallucination Guard (Schema.org Parity)",
        "spec_ref": "schema.org/Offer + ucp.dev/specification/checkout",
    },
    {
        "gate_number": 9,
        "gate_id": "UCP-09",
        "weight": 10,
        "title": "AP2 Payment Mandate & Idempotency / Replay Protection",
        "spec_ref": "ucp.dev/specification/ap2-mandate",
    },
    {
        "gate_number": 10,
        "gate_id": "UCP-10",
        "weight": 10,
        "title": "Edge Discovery Headers (JSON MIME, CORS, Cache) & 1-Click Bundle",
        "spec_ref": "rfc8615 + ucp.dev/specification/discovery",
    },
)

OFFICIAL_UCP_SERVICES: frozenset[str] = frozenset({"dev.ucp.shopping"})
OFFICIAL_UCP_CAPABILITIES: frozenset[str] = frozenset(
    {
        "dev.ucp.shopping.checkout",
        "dev.ucp.shopping.fulfillment",
        "dev.ucp.shopping.discount",
        "dev.ucp.shopping.order",
        "dev.ucp.shopping.cart",
        "dev.ucp.shopping.catalog",
        "dev.ucp.shopping.ap2_mandate",
        "dev.ucp.identity_linking",
    }
)
CHECKOUT_EXTENSION_CAPABILITIES: frozenset[str] = frozenset(
    {
        "dev.ucp.shopping.fulfillment",
        "dev.ucp.shopping.discount",
        "dev.ucp.shopping.ap2_mandate",
    }
)
ALLOWED_TRANSPORTS: frozenset[str] = frozenset({"rest", "mcp", "a2a", "embedded"})

_DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")
_EMBEDDED_DATE_RE = re.compile(r"\b(20\d{2}-\d{2}-\d{2})\b")
_SERVICE_NS_RE = re.compile(r"^[a-z]{2,16}(?:\.[a-z0-9_]+){2,}$")
_CAPABILITY_NS_RE = re.compile(r"^[a-z]{2,16}(?:\.[a-z0-9_]+){3,}$")
_HANDLER_NS_RE = re.compile(r"^[a-z]{2,16}(?:\.[a-z0-9_]+){2,}$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_SECRET_LEAK_RE = re.compile(
    r"\b(?:sk_live_[A-Za-z0-9]{10,}|sk_test_[A-Za-z0-9]{10,}|rk_live_[A-Za-z0-9]{10,}|"
    r"whsec_[A-Za-z0-9]{10,}|shpat_[A-Za-z0-9]{10,}|shpss_[A-Za-z0-9]{10,}|shpca_[A-Za-z0-9]{10,})\b"
)
_JSON_LD_SCRIPT_RE = re.compile(
    r"<script\b[^>]*type\s*=\s*[\"']application/ld\+json[\"'][^>]*>(.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)

_FORBIDDEN_HOSTS: frozenset[str] = frozenset(
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
_FORBIDDEN_HOST_SUFFIXES = (".local", ".internal", ".localhost", ".home.arpa")
_TEST_TLD_PREFIXES = ("local.", "test.", "invalid.", "localhost.", "internal.")
_VALID_SCHEMA_AVAILABILITIES: frozenset[str] = frozenset(
    {
        "instock",
        "outofstock",
        "preorder",
        "presale",
        "limitedavailability",
        "onlineonly",
        "instoreonly",
        "backorder",
        "soldout",
        "discontinued",
    }
)


class UcpParseError(ValueError):
    """Raised when a UCP manifest or audit bundle cannot be parsed."""


@dataclass(frozen=True)
class GateFinding:
    """Single actionable finding within a UCP readiness gate."""

    code: str
    severity: str
    title: str
    remediation: str

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "severity": self.severity,
            "title": self.title,
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class GateResult:
    """Evaluation result for one of the 10 UCP readiness gates."""

    gate_number: int
    gate_id: str
    title: str
    spec_ref: str
    weight: int
    earned_points: int
    status: str
    summary: str
    findings: list[GateFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate_number": self.gate_number,
            "gate_id": self.gate_id,
            "title": self.title,
            "spec_ref": self.spec_ref,
            "weight": self.weight,
            "earned_points": self.earned_points,
            "status": self.status,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass(frozen=True)
class UcpAuditReport:
    """Complete 10-gate UCP + AP2 + A2A readiness audit report."""

    domain: str
    ucp_version: str | None
    status: str
    score: int
    grade: str
    gates_passed: int
    gates_warned: int
    gates_failed: int
    findings_count: int
    gates: list[GateResult]
    dag: dict[str, Any]
    detected_offers: list[dict[str, Any]]
    surfaces: dict[str, Any]
    deployment_bundle: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "ucp_version": self.ucp_version,
            "status": self.status,
            "score": self.score,
            "grade": self.grade,
            "gates_passed": self.gates_passed,
            "gates_warned": self.gates_warned,
            "gates_failed": self.gates_failed,
            "findings_count": self.findings_count,
            "gates": [g.to_dict() for g in self.gates],
            "dag": self.dag,
            "detected_offers": self.detected_offers,
            "surfaces": self.surfaces,
            "deployment_bundle": self.deployment_bundle,
        }


def strip_jsonc_comments(raw_text: str) -> str:
    """Strip // and /* */ comments outside JSON string literals."""
    out: list[str] = []
    i = 0
    n = len(raw_text)
    in_str = False
    escaped = False

    while i < n:
        ch = raw_text[i]
        if in_str:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            i += 1
            continue

        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue

        if ch == "/" and i + 1 < n and raw_text[i + 1] == "/":
            i += 2
            while i < n and raw_text[i] not in ("\n", "\r"):
                i += 1
            continue

        if ch == "/" and i + 1 < n and raw_text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (raw_text[i] == "*" and raw_text[i + 1] == "/"):
                if raw_text[i] in ("\n", "\r"):
                    out.append(raw_text[i])
                i += 1
            i += 2
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def _is_valid_calendar_date(val: Any) -> tuple[bool, str | None]:
    if not isinstance(val, str):
        return False, None
    m = _DATE_RE.match(val.strip())
    if not m:
        return False, None
    year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
    try:
        dt.date(year, month, day)
    except ValueError:
        return False, None
    return True, val.strip()


def _is_non_global_ip_literal(host: str) -> tuple[bool, bool]:
    """Return (is_ip_literal, is_blocked_ssrf_ip)."""
    clean = host.strip().lower()
    if clean.startswith("[") and clean.endswith("]"):
        clean = clean[1:-1]
    if "%" in clean:
        clean = clean.split("%", 1)[0]
    try:
        ip_obj = ipaddress.ip_address(clean)
    except ValueError:
        return False, False

    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped

    if isinstance(ip_obj, ipaddress.IPv4Address):
        packed = int(ip_obj)
        # CGNAT 100.64.0.0/10 and Benchmarking 198.18.0.0/15 explicit checks across Python versions
        in_cgnat = (packed & 0xFFC00000) == 0x64400000
        in_benchmark = (packed & 0xFFFE0000) == 0xC6120000
        blocked = (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
            or in_cgnat
            or in_benchmark
            or not ip_obj.is_global
        )
        return True, blocked

    blocked_v6 = (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
        or not ip_obj.is_global
    )
    return True, blocked_v6


def inspect_https_public_url(raw_url: Any) -> dict[str, Any]:
    """Deterministically inspect a UCP endpoint/schema/spec URL for HTTPS and SSRF safety."""
    if not isinstance(raw_url, str) or not raw_url.strip():
        return {"ok": False, "reason": "MISSING_URL", "detail": "URL is missing or empty.", "host": ""}

    s = raw_url.strip()
    parsed = urlparse(s)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if scheme not in ("https", "http"):
        return {
            "ok": False,
            "reason": "INVALID_URI_SCHEME",
            "detail": f"Only https:// URLs are permitted (got {scheme or 'none'}): {s}",
            "host": "",
        }
    if parsed.username or parsed.password:
        return {
            "ok": False,
            "reason": "EMBEDDED_CREDENTIALS",
            "detail": "Embedded URL userinfo credentials are disallowed.",
            "host": host,
        }
    if not host:
        return {"ok": False, "reason": "MISSING_HOSTNAME", "detail": f"Missing hostname in URL: {s}", "host": ""}

    if host in _FORBIDDEN_HOSTS or any(host.endswith(sfx) for sfx in _FORBIDDEN_HOST_SUFFIXES):
        return {
            "ok": False,
            "reason": "SSRF_RESERVED_HOST",
            "detail": f"Reserved/internal hostname blocked (SSRF risk): {host}",
            "host": host,
        }

    is_ip, is_blocked_ip = _is_non_global_ip_literal(host)
    if is_ip and is_blocked_ip:
        return {
            "ok": False,
            "reason": "SSRF_PRIVATE_IP",
            "detail": f"Private, loopback, link-local, or reserved IP literal blocked (SSRF risk): {host}",
            "host": host,
        }

    if scheme == "http":
        return {
            "ok": False,
            "reason": "CLEARTEXT_HTTP_URL",
            "detail": f"Cleartext HTTP URL disallowed in UCP: {s}",
            "host": host,
        }

    if not is_ip and ("." not in host or len(host.rsplit(".", 1)[-1]) < 2):
        return {
            "ok": False,
            "reason": "INVALID_PUBLIC_HOST",
            "detail": f"Hostname is not a valid public DNS domain: {host}",
            "host": host,
        }

    return {
        "ok": True,
        "reason": "OK",
        "detail": "",
        "host": host,
        "path": parsed.path or "/",
        "has_fragment": bool(parsed.fragment),
        "has_query": bool(parsed.query),
    }


def extract_schema_org_offers_from_html(html: str) -> list[dict[str, Any]]:
    """Extract normalized Schema.org Offer / AggregateOffer records from HTML JSON-LD."""
    if not isinstance(html, str) or not html.strip():
        return []

    offers: list[dict[str, Any]] = []

    def _visit(node: Any, parent_name: str = "", parent_sku: str = "") -> None:
        if isinstance(node, list):
            for child in node:
                _visit(child, parent_name=parent_name, parent_sku=parent_sku)
            return
        if not isinstance(node, dict):
            return

        if "@graph" in node and isinstance(node["@graph"], list):
            _visit(node["@graph"], parent_name=parent_name, parent_sku=parent_sku)

        raw_type = node.get("@type")
        type_list = [str(t) for t in raw_type] if isinstance(raw_type, list) else ([str(raw_type)] if raw_type else [])
        norm_types = {t.rsplit("/", 1)[-1].lower() for t in type_list}

        cur_name = str(node.get("name") or parent_name or "").strip()
        cur_sku = str(node.get("sku") or parent_sku or "").strip()

        if "product" in norm_types and "offers" in node:
            _visit(node["offers"], parent_name=cur_name, parent_sku=cur_sku)
            return

        if "offer" in norm_types or "aggregateoffer" in norm_types:
            raw_price = node.get("price")
            if raw_price is None:
                raw_price = node.get("lowPrice")
            offers.append(
                {
                    "name": cur_name or "Unnamed Product",
                    "sku": cur_sku,
                    "price": raw_price,
                    "price_currency": str(node.get("priceCurrency") or "").strip(),
                    "availability": str(node.get("availability") or "").strip(),
                }
            )
            if "offers" in node:
                _visit(node["offers"], parent_name=cur_name, parent_sku=cur_sku)

    for match in _JSON_LD_SCRIPT_RE.finditer(html):
        raw_block = match.group(1).strip()
        if not raw_block:
            continue
        try:
            parsed = json.loads(raw_block)
        except json.JSONDecodeError:
            continue
        _visit(parsed)

    return offers


def inspect_capability_dag(capabilities: Any) -> dict[str, Any]:
    """Build and verify the UCP capability inheritance DAG (`extends`)."""
    if not isinstance(capabilities, dict):
        return {
            "nodes": [],
            "edges": [],
            "dangling_parents": [],
            "cycles": [],
            "invalid_extends": [],
            "missing_checkout_inheritance": [],
            "is_acyclic": True,
            "topological_order": [],
        }

    nodes = list(capabilities.keys())
    node_set = set(nodes)
    parents_map: dict[str, list[str]] = {k: [] for k in nodes}
    edges: list[dict[str, str]] = []
    dangling_parents: list[dict[str, str]] = []
    invalid_extends: list[dict[str, str]] = []
    cycles: list[list[str]] = []

    for cap_key, descriptors in capabilities.items():
        if not isinstance(descriptors, list):
            continue
        for desc in descriptors:
            if not isinstance(desc, dict) or "extends" not in desc or desc["extends"] is None:
                continue
            ext_val = desc["extends"]
            parent_list: list[str] = []
            if isinstance(ext_val, str):
                if not ext_val.strip():
                    invalid_extends.append({"capability": cap_key, "detail": "Empty extends string."})
                else:
                    parent_list.append(ext_val.strip())
            elif isinstance(ext_val, list):
                if not ext_val or not all(isinstance(x, str) and x.strip() for x in ext_val):
                    invalid_extends.append(
                        {"capability": cap_key, "detail": "extends array must contain non-empty strings."}
                    )
                else:
                    parent_list.extend(x.strip() for x in ext_val)
            else:
                invalid_extends.append(
                    {"capability": cap_key, "detail": "extends must be a capability string or string array."}
                )

            for parent in parent_list:
                edges.append({"from": cap_key, "to": parent})
                if parent == cap_key:
                    cycles.append([cap_key, cap_key])
                elif parent not in node_set:
                    dangling_parents.append({"capability": cap_key, "missing_parent": parent})
                else:
                    if parent not in parents_map[cap_key]:
                        parents_map[cap_key].append(parent)

    # Deterministic 3-color DFS to detect multi-node cycles
    color: dict[str, int] = {k: 0 for k in nodes}
    stack: list[str] = []
    recorded_cycle_keys: set[str] = set()
    topo_order: list[str] = []

    def _dfs(node: str) -> None:
        color[node] = 1
        stack.append(node)
        for parent in parents_map[node]:
            if color[parent] == 0:
                _dfs(parent)
            elif color[parent] == 1:
                idx = stack.index(parent)
                cyc = stack[idx:] + [parent]
                # Canonicalize cycle key to avoid duplicate cycle reports
                ring = cyc[:-1]
                min_pos = min(range(len(ring)), key=lambda i: ring[i])
                canon = "->".join(ring[min_pos:] + ring[:min_pos])
                if canon not in recorded_cycle_keys:
                    recorded_cycle_keys.add(canon)
                    cycles.append(cyc)
        stack.pop()
        color[node] = 2
        topo_order.append(node)

    for node in nodes:
        if color[node] == 0:
            _dfs(node)

    is_acyclic = len(cycles) == 0

    # Verify standard UCP checkout extensions reach dev.ucp.shopping.checkout
    missing_checkout_inheritance: list[str] = []
    if is_acyclic:
        for ext_cap in CHECKOUT_EXTENSION_CAPABILITIES:
            if ext_cap not in node_set:
                continue
            visited: set[str] = set()
            queue = list(parents_map.get(ext_cap, []))
            reaches_checkout = False
            while queue:
                cur = queue.pop(0)
                if cur == "dev.ucp.shopping.checkout":
                    reaches_checkout = True
                    break
                if cur not in visited:
                    visited.add(cur)
                    queue.extend(parents_map.get(cur, []))
            if not reaches_checkout:
                missing_checkout_inheritance.append(ext_cap)

    return {
        "nodes": nodes,
        "edges": edges,
        "dangling_parents": dangling_parents,
        "cycles": cycles,
        "invalid_extends": invalid_extends,
        "missing_checkout_inheritance": sorted(missing_checkout_inheritance),
        "is_acyclic": is_acyclic,
        "topological_order": topo_order if is_acyclic else [],
    }


def _make_gate_result(
    gate_index: int,
    status: str,
    summary: str,
    findings: list[GateFinding],
) -> GateResult:
    gdef = GATE_DEFINITIONS[gate_index]
    weight = int(gdef["weight"])
    if status == "pass":
        earned = weight
    elif status == "warn":
        earned = weight // 2
    else:
        earned = 0
    return GateResult(
        gate_number=int(gdef["gate_number"]),
        gate_id=str(gdef["gate_id"]),
        title=str(gdef["title"]),
        spec_ref=str(gdef["spec_ref"]),
        weight=weight,
        earned_points=earned,
        status=status,
        summary=summary,
        findings=findings,
    )


def _infer_store_domain(bundle: dict[str, Any], ucp_obj: dict[str, Any] | None) -> str:
    raw_dom = bundle.get("domain")
    if isinstance(raw_dom, str) and raw_dom.strip():
        try:
            return normalize_store_domain(raw_dom)
        except ValueError:
            pass

    if isinstance(ucp_obj, dict):
        services = ucp_obj.get("services")
        if isinstance(services, dict):
            for bindings in services.values():
                if isinstance(bindings, list):
                    for b in bindings:
                        if isinstance(b, dict) and isinstance(b.get("endpoint"), str):
                            info = inspect_https_public_url(b["endpoint"])
                            if info["ok"] and info["host"]:
                                try:
                                    return normalize_store_domain(info["host"])
                                except ValueError:
                                    pass

    return "nordic-roast.shop"


def _infer_platform(ucp_obj: dict[str, Any] | None) -> str:
    if isinstance(ucp_obj, dict):
        services = ucp_obj.get("services")
        if isinstance(services, dict):
            shopping = services.get("dev.ucp.shopping")
            if isinstance(shopping, list):
                transports = [
                    str(b.get("transport") or "").lower()
                    for b in shopping
                    if isinstance(b, dict)
                ]
                endpoints = [
                    str(b.get("endpoint") or "").lower()
                    for b in shopping
                    if isinstance(b, dict)
                ]
                if any("/api/ucp" in ep or "myshopify" in ep for ep in endpoints):
                    return "shopify"
                if "mcp" in transports:
                    return "stateless_mcp"
                if "rest" in transports:
                    return "custom_rest"
    return "shopify"


def _letter_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def audit_ucp_text(raw_text: str) -> UcpAuditReport:
    """Parse a JSON/JSONC UCP manifest or audit bundle string and run all 10 gates."""
    if not isinstance(raw_text, str) or not raw_text.strip():
        raise UcpParseError("Input UCP manifest text is empty.")
    cleaned = strip_jsonc_comments(raw_text).strip()
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise UcpParseError(f"Invalid JSON in UCP input: {exc}") from exc
    if not isinstance(parsed, dict):
        raise UcpParseError("Root UCP payload must be a JSON object.")
    return audit_ucp_readiness(parsed)


def audit_ucp_readiness(payload: dict[str, Any]) -> UcpAuditReport:
    """Run all 10 Agentic Commerce readiness gates on a UCP manifest or composite bundle."""
    if not isinstance(payload, dict):
        raise UcpParseError("UCP payload must be a dictionary.")

    if "manifest" in payload and isinstance(payload["manifest"], dict):
        bundle = dict(payload)
        manifest_doc: Any = payload["manifest"]
    elif "ucp" in payload:
        bundle = dict(payload)
        manifest_doc = {"ucp": payload["ucp"]}
    else:
        bundle = dict(payload)
        manifest_doc = payload.get("manifest", payload)

    ucp_obj = manifest_doc.get("ucp") if isinstance(manifest_doc, dict) else None
    inferred_domain = _infer_store_domain(bundle, ucp_obj if isinstance(ucp_obj, dict) else None)
    inferred_platform = str(bundle.get("platform") or _infer_platform(ucp_obj if isinstance(ucp_obj, dict) else None))

    gates: list[GateResult] = []

    # -------------------------------------------------------------------------
    # UCP-01: Valid ucp.version (YYYY-MM-DD, >= 2026-01-01) & top-level envelope
    # -------------------------------------------------------------------------
    g1_findings: list[GateFinding] = []
    root_version: str | None = None
    if not isinstance(ucp_obj, dict):
        g1_findings.append(
            GateFinding(
                code="MISSING_UCP_ENVELOPE",
                severity="critical",
                title="Missing top-level 'ucp' JSON object in /.well-known/ucp.",
                remediation="Wrap protocol version, services, capabilities, and payment_handlers inside {\"ucp\": {...}}.",
            )
        )
        g1_status = "fail"
        g1_summary = "Manifest lacks the required top-level 'ucp' object."
    else:
        raw_ver = ucp_obj.get("version")
        ok_date, clean_ver = _is_valid_calendar_date(raw_ver)
        if not ok_date or clean_ver is None:
            g1_findings.append(
                GateFinding(
                    code="INVALID_UCP_VERSION_FORMAT",
                    severity="critical",
                    title=f"ucp.version must be a valid YYYY-MM-DD calendar date (got {raw_ver!r}).",
                    remediation=f"Set \"version\": \"{DEFAULT_UCP_VERSION}\" on the root ucp object.",
                )
            )
        elif clean_ver < "2026-01-01":
            root_version = clean_ver
            g1_findings.append(
                GateFinding(
                    code="OUTDATED_PRE_2026_UCP_VERSION",
                    severity="high",
                    title=f"ucp.version {clean_ver} predates the 2026-01-23 UCP public specification.",
                    remediation=f"Upgrade ucp.version to \"{DEFAULT_UCP_VERSION}\" or newer.",
                )
            )
        else:
            root_version = clean_ver

        for sec_name in ("services", "capabilities"):
            sec_val = ucp_obj.get(sec_name)
            if not isinstance(sec_val, dict):
                g1_findings.append(
                    GateFinding(
                        code=f"INVALID_{sec_name.upper()}_OBJECT",
                        severity="critical",
                        title=f"ucp.{sec_name} must be a JSON object mapping reverse-domain keys to descriptor arrays.",
                        remediation=f"Define ucp.{sec_name} as a non-empty JSON object.",
                    )
                )

        has_critical_g1 = any(f.severity in ("critical", "high") for f in g1_findings)
        if not has_critical_g1 and root_version is not None:
            # Check child descriptor version drift
            drift_count = 0
            for sec_name in ("services", "capabilities", "payment_handlers"):
                sec_val = ucp_obj.get(sec_name)
                if isinstance(sec_val, dict):
                    for items in sec_val.values():
                        if isinstance(items, list):
                            for item in items:
                                if isinstance(item, dict):
                                    iv_ok, iv_str = _is_valid_calendar_date(item.get("version"))
                                    if not iv_ok or iv_str != root_version:
                                        drift_count += 1
            if drift_count > 0:
                g1_findings.append(
                    GateFinding(
                        code="DESCRIPTOR_VERSION_DRIFT",
                        severity="medium",
                        title=f"{drift_count} descriptor(s) omit or mismatch root ucp.version ({root_version}).",
                        remediation=f"Align every service, capability, and payment_handler version to \"{root_version}\".",
                    )
                )
                g1_status = "warn"
                g1_summary = f"Root ucp.version ({root_version}) is valid, but {drift_count} child descriptor(s) drift."
            else:
                g1_status = "pass"
                g1_summary = f"Valid ucp.version ({root_version}) and aligned top-level envelope."
        else:
            g1_status = "fail"
            g1_summary = "Invalid ucp.version date or malformed top-level UCP envelope."

    gates.append(_make_gate_result(0, g1_status, g1_summary, g1_findings))

    services_obj = ucp_obj.get("services") if isinstance(ucp_obj, dict) and isinstance(ucp_obj.get("services"), dict) else {}
    caps_obj = (
        ucp_obj.get("capabilities")
        if isinstance(ucp_obj, dict) and isinstance(ucp_obj.get("capabilities"), dict)
        else {}
    )
    handlers_obj: dict[str, Any] = {}
    used_legacy_payment_block = False
    if isinstance(ucp_obj, dict):
        if isinstance(ucp_obj.get("payment_handlers"), dict):
            handlers_obj = ucp_obj["payment_handlers"]
        elif isinstance(ucp_obj.get("payment"), dict) and isinstance(ucp_obj["payment"].get("handlers"), dict):
            handlers_obj = ucp_obj["payment"]["handlers"]
            used_legacy_payment_block = True

    # -------------------------------------------------------------------------
    # UCP-02: Reverse-Domain Namespace Syntax & Collision Safety
    # -------------------------------------------------------------------------
    g2_findings: list[GateFinding] = []
    if not services_obj and not caps_obj:
        g2_findings.append(
            GateFinding(
                code="EMPTY_NAMESPACES",
                severity="critical",
                title="No service or capability namespaces declared in /.well-known/ucp.",
                remediation="Declare dev.ucp.shopping in services and dev.ucp.shopping.checkout in capabilities.",
            )
        )
    else:
        for s_key in services_obj:
            if not _SERVICE_NS_RE.match(s_key):
                g2_findings.append(
                    GateFinding(
                        code="INVALID_SERVICE_NAMESPACE",
                        severity="high",
                        title=f"Service key {s_key!r} violates reverse-domain syntax ({{tld}}.{{domain}}.{{service}}).",
                        remediation="Use lowercase reverse-domain identifiers such as 'dev.ucp.shopping'.",
                    )
                )
            elif s_key.startswith("dev.ucp.") and s_key not in OFFICIAL_UCP_SERVICES:
                g2_findings.append(
                    GateFinding(
                        code="RESERVED_UCP_SERVICE_SQUATTING",
                        severity="high",
                        title=f"Service key {s_key!r} squats on reserved dev.ucp.* namespace.",
                        remediation="Place vendor-specific services under your own reverse domain (e.g. 'shop.brand.catalog').",
                    )
                )
            elif s_key.startswith(_TEST_TLD_PREFIXES):
                g2_findings.append(
                    GateFinding(
                        code="TEST_TLD_NAMESPACE",
                        severity="medium",
                        title=f"Service namespace {s_key!r} uses a non-routable test TLD prefix.",
                        remediation="Use a verified public reverse-domain prefix.",
                    )
                )

        for c_key in caps_obj:
            valid_cap_syntax = c_key == "dev.ucp.identity_linking" or bool(_CAPABILITY_NS_RE.match(c_key))
            if not valid_cap_syntax:
                g2_findings.append(
                    GateFinding(
                        code="INVALID_CAPABILITY_NAMESPACE",
                        severity="high",
                        title=f"Capability key {c_key!r} violates 4-segment reverse-domain grammar ({{tld}}.{{domain}}.{{service}}.{{capability}}).",
                        remediation="Rename capability to reverse-domain format such as 'dev.ucp.shopping.checkout'.",
                    )
                )
            elif c_key.startswith("dev.ucp.") and c_key not in OFFICIAL_UCP_CAPABILITIES:
                g2_findings.append(
                    GateFinding(
                        code="RESERVED_UCP_CAPABILITY_SQUATTING",
                        severity="high",
                        title=f"Capability {c_key!r} squats on reserved official dev.ucp.* namespace.",
                        remediation="Namespace custom capabilities under your merchant reverse domain (e.g. 'shop.brand.shopping.loyalty').",
                    )
                )
            elif c_key.startswith(_TEST_TLD_PREFIXES):
                g2_findings.append(
                    GateFinding(
                        code="TEST_TLD_NAMESPACE",
                        severity="medium",
                        title=f"Capability namespace {c_key!r} uses a test TLD prefix.",
                        remediation="Use a production reverse-domain prefix.",
                    )
                )

        for h_key in handlers_obj:
            valid_handler_syntax = h_key == "shop.pay" or bool(_HANDLER_NS_RE.match(h_key))
            if not valid_handler_syntax:
                g2_findings.append(
                    GateFinding(
                        code="INVALID_PAYMENT_HANDLER_NAMESPACE",
                        severity="high",
                        title=f"Payment handler key {h_key!r} violates reverse-domain syntax.",
                        remediation="Use canonical handler keys: 'com.google.pay', 'com.stripe.pay', or 'shop.pay'.",
                    )
                )

    if any(f.severity in ("critical", "high") for f in g2_findings):
        g2_status = "fail"
        g2_summary = "One or more keys violate reverse-domain grammar or squat on reserved dev.ucp.* namespaces."
    elif g2_findings:
        g2_status = "warn"
        g2_summary = "Reverse-domain syntax parses, with test-TLD namespace warnings."
    else:
        total_ns = len(services_obj) + len(caps_obj) + len(handlers_obj)
        g2_status = "pass"
        g2_summary = f"All {total_ns} service, capability, and payment_handler namespaces pass collision-safe grammar."

    gates.append(_make_gate_result(1, g2_status, g2_summary, g2_findings))

    # -------------------------------------------------------------------------
    # UCP-03: services transport (rest / mcp), HTTPS-only endpoint & SSRF guard
    # -------------------------------------------------------------------------
    g3_findings: list[GateFinding] = []
    shopping_bindings = services_obj.get("dev.ucp.shopping")
    seen_bindings: set[tuple[str, str]] = set()
    valid_transports_found: list[str] = []

    if not isinstance(shopping_bindings, list) or len(shopping_bindings) == 0:
        g3_findings.append(
            GateFinding(
                code="MISSING_SHOPPING_SERVICE",
                severity="critical",
                title="ucp.services['dev.ucp.shopping'] is missing or empty.",
                remediation="Declare at least one HTTPS 'rest' or 'mcp' transport binding under dev.ucp.shopping.",
            )
        )
    else:
        for idx, binding in enumerate(shopping_bindings):
            if not isinstance(binding, dict):
                g3_findings.append(
                    GateFinding(
                        code="MALFORMED_SERVICE_BINDING",
                        severity="high",
                        title=f"dev.ucp.shopping[{idx}] must be a JSON object.",
                        remediation="Provide version, spec, transport, endpoint, and schema fields.",
                    )
                )
                continue

            transport = str(binding.get("transport") or "").strip().lower()
            if transport not in ALLOWED_TRANSPORTS:
                g3_findings.append(
                    GateFinding(
                        code="UNSUPPORTED_SERVICE_TRANSPORT",
                        severity="high",
                        title=f"dev.ucp.shopping[{idx}] uses unsupported transport {transport!r}.",
                        remediation="Set transport to 'rest', 'mcp', or 'a2a'.",
                    )
                )
            else:
                if transport not in valid_transports_found:
                    valid_transports_found.append(transport)

            ep_info = inspect_https_public_url(binding.get("endpoint"))
            if not ep_info["ok"]:
                g3_findings.append(
                    GateFinding(
                        code=f"ENDPOINT_{ep_info['reason']}",
                        severity="critical",
                        title=f"dev.ucp.shopping[{idx}].endpoint rejected: {ep_info['detail']}",
                        remediation="Expose UCP endpoints exclusively over public TLS (https://) on a routable domain.",
                    )
                )
            elif ep_info.get("has_fragment"):
                g3_findings.append(
                    GateFinding(
                        code="ENDPOINT_URI_FRAGMENT",
                        severity="high",
                        title=f"dev.ucp.shopping[{idx}].endpoint must not contain a #fragment.",
                        remediation="Remove URL fragments from service endpoints.",
                    )
                )

            sc_info = inspect_https_public_url(binding.get("schema"))
            if not sc_info["ok"]:
                g3_findings.append(
                    GateFinding(
                        code=f"SCHEMA_{sc_info['reason']}",
                        severity="high",
                        title=f"dev.ucp.shopping[{idx}].schema rejected: {sc_info['detail']}",
                        remediation="Reference a public https:// OpenAPI or OpenRPC JSON schema URL.",
                    )
                )

            spec_raw = binding.get("spec")
            if spec_raw is None or str(spec_raw).strip() == "":
                g3_findings.append(
                    GateFinding(
                        code="MISSING_SERVICE_SPEC_URL",
                        severity="medium",
                        title=f"dev.ucp.shopping[{idx}] omits 'spec' documentation URL.",
                        remediation="Add \"spec\": \"https://ucp.dev/specification/overview\".",
                    )
                )
            else:
                sp_info = inspect_https_public_url(spec_raw)
                if not sp_info["ok"]:
                    g3_findings.append(
                        GateFinding(
                            code=f"SPEC_{sp_info['reason']}",
                            severity="high",
                            title=f"dev.ucp.shopping[{idx}].spec rejected: {sp_info['detail']}",
                            remediation="Use an https:// specification URL.",
                        )
                    )

            if ep_info["ok"] and transport:
                pair = (transport, str(binding.get("endpoint")).strip())
                if pair in seen_bindings:
                    g3_findings.append(
                        GateFinding(
                            code="DUPLICATE_SERVICE_BINDING",
                            severity="medium",
                            title=f"Duplicate ({transport}, {pair[1]}) binding in dev.ucp.shopping.",
                            remediation="Deduplicate identical transport + endpoint entries.",
                        )
                    )
                seen_bindings.add(pair)

    if any(f.severity in ("critical", "high") for f in g3_findings):
        g3_status = "fail"
        g3_summary = "Service bindings failed HTTPS-only, SSRF/private-IP, transport, or schema checks."
    elif g3_findings:
        g3_status = "warn"
        g3_summary = "Service endpoints are public HTTPS, with minor spec/duplication warnings."
    else:
        g3_status = "pass"
        g3_summary = f"Verified public HTTPS endpoints and schemas across {', '.join(valid_transports_found)} transport(s)."

    gates.append(_make_gate_result(2, g3_status, g3_summary, g3_findings))

    # -------------------------------------------------------------------------
    # UCP-04: Core dev.ucp.shopping.checkout completeness & spec/schema alignment
    # -------------------------------------------------------------------------
    g4_findings: list[GateFinding] = []
    checkout_list = caps_obj.get("dev.ucp.shopping.checkout")
    if not isinstance(checkout_list, list) or len(checkout_list) == 0:
        g4_findings.append(
            GateFinding(
                code="MISSING_CHECKOUT_CAPABILITY",
                severity="critical",
                title="Core capability 'dev.ucp.shopping.checkout' is missing from ucp.capabilities.",
                remediation="Declare dev.ucp.shopping.checkout with version, spec, and https:// checkout.json schema.",
            )
        )
    else:
        for cap_key, desc_list in caps_obj.items():
            if not isinstance(desc_list, list) or len(desc_list) == 0:
                g4_findings.append(
                    GateFinding(
                        code="EMPTY_CAPABILITY_DESCRIPTORS",
                        severity="high",
                        title=f"Capability {cap_key!r} must contain a non-empty array of descriptors.",
                        remediation=f"Provide at least one descriptor object for {cap_key}.",
                    )
                )
                continue
            for idx, desc in enumerate(desc_list):
                if not isinstance(desc, dict):
                    g4_findings.append(
                        GateFinding(
                            code="MALFORMED_CAPABILITY_DESCRIPTOR",
                            severity="high",
                            title=f"{cap_key}[{idx}] must be a JSON object.",
                            remediation="Provide version, spec, and schema fields.",
                        )
                    )
                    continue
                sp_check = inspect_https_public_url(desc.get("spec"))
                sc_check = inspect_https_public_url(desc.get("schema"))
                if not sp_check["ok"]:
                    g4_findings.append(
                        GateFinding(
                            code="INVALID_CAPABILITY_SPEC_URL",
                            severity="high",
                            title=f"{cap_key}[{idx}].spec invalid: {sp_check['detail']}",
                            remediation="Set spec to a public https:// specification URL.",
                        )
                    )
                if not sc_check["ok"]:
                    g4_findings.append(
                        GateFinding(
                            code="INVALID_CAPABILITY_SCHEMA_URL",
                            severity="high",
                            title=f"{cap_key}[{idx}].schema invalid: {sc_check['detail']}",
                            remediation="Set schema to a public https:// JSON Schema URL.",
                        )
                    )
                else:
                    schema_str = str(desc.get("schema") or "").strip()
                    if not schema_str.lower().endswith(".json"):
                        g4_findings.append(
                            GateFinding(
                                code="NON_JSON_CAPABILITY_SCHEMA_PATH",
                                severity="medium",
                                title=f"{cap_key}[{idx}].schema ({schema_str}) does not end with .json.",
                                remediation="Point capability schema to an explicit .json JSON Schema artifact.",
                            )
                        )
                    ok_dv, desc_ver = _is_valid_calendar_date(desc.get("version"))
                    embedded_dates = _EMBEDDED_DATE_RE.findall(schema_str)
                    if ok_dv and desc_ver and embedded_dates and desc_ver not in embedded_dates:
                        g4_findings.append(
                            GateFinding(
                                code="CAPABILITY_SCHEMA_VERSION_MISMATCH",
                                severity="medium",
                                title=f"{cap_key}[{idx}] version ({desc_ver}) mismatches schema URL date ({embedded_dates[0]}).",
                                remediation=f"Use matching {desc_ver} schema path in {cap_key}.",
                            )
                        )

    if any(f.severity in ("critical", "high") for f in g4_findings):
        g4_status = "fail"
        g4_summary = "Core dev.ucp.shopping.checkout is missing or capability spec/schema URLs are invalid."
    elif g4_findings:
        g4_status = "warn"
        g4_summary = "dev.ucp.shopping.checkout is present, with minor schema path/version alignment warnings."
    else:
        g4_status = "pass"
        g4_summary = f"dev.ucp.shopping.checkout and {len(caps_obj)} total capability contract(s) verified."

    gates.append(_make_gate_result(3, g4_status, g4_summary, g4_findings))

    # -------------------------------------------------------------------------
    # UCP-05: Capability composition DAG (extends resolution & cycle check)
    # -------------------------------------------------------------------------
    dag_info = inspect_capability_dag(caps_obj)
    g5_findings: list[GateFinding] = []

    if not caps_obj:
        g5_findings.append(
            GateFinding(
                code="EMPTY_CAPABILITY_DAG",
                severity="critical",
                title="Cannot verify capability composition graph because ucp.capabilities is empty.",
                remediation="Declare dev.ucp.shopping.checkout and its extension DAG.",
            )
        )
    for inv in dag_info["invalid_extends"]:
        g5_findings.append(
            GateFinding(
                code="INVALID_EXTENDS_FIELD",
                severity="high",
                title=f"{inv['capability']}: {inv['detail']}",
                remediation="Set extends to a parent capability namespace string (e.g. 'dev.ucp.shopping.checkout').",
            )
        )
    for dang in dag_info["dangling_parents"]:
        g5_findings.append(
            GateFinding(
                code="DANGLING_EXTENDS_PARENT",
                severity="critical",
                title=f"Capability {dang['capability']!r} extends undeclared parent {dang['missing_parent']!r}.",
                remediation=f"Declare {dang['missing_parent']!r} in ucp.capabilities or fix the extends target.",
            )
        )
    for cyc in dag_info["cycles"]:
        cycle_path = " -> ".join(cyc)
        g5_findings.append(
            GateFinding(
                code="CAPABILITY_EXTENDS_CYCLE",
                severity="critical",
                title=f"Cycle detected in capability extends graph: {cycle_path}.",
                remediation="Break circular extends references so capability inheritance forms a strict DAG rooted at checkout.",
            )
        )
    for orphan_ext in dag_info["missing_checkout_inheritance"]:
        g5_findings.append(
            GateFinding(
                code="MISSING_CANONICAL_CHECKOUT_EXTENDS",
                severity="medium",
                title=f"Extension {orphan_ext!r} omits \"extends\": \"dev.ucp.shopping.checkout\".",
                remediation=f"Add \"extends\": \"dev.ucp.shopping.checkout\" to {orphan_ext}.",
            )
        )

    if any(f.severity in ("critical", "high") for f in g5_findings):
        g5_status = "fail"
        g5_summary = "Capability inheritance graph contains cycles, dangling parents, or invalid extends syntax."
    elif g5_findings:
        g5_status = "warn"
        g5_summary = "Capability graph is acyclic, but standard shopping extensions omit explicit checkout inheritance."
    else:
        g5_status = "pass"
        g5_summary = (
            f"Acyclic capability DAG verified ({len(dag_info['nodes'])} node(s), "
            f"{len(dag_info['edges'])} extends edge(s))."
        )

    gates.append(_make_gate_result(4, g5_status, g5_summary, g5_findings))

    # -------------------------------------------------------------------------
    # UCP-06: payment_handlers UUID, version, HTTPS schemas & secret leak guard
    # -------------------------------------------------------------------------
    g6_findings: list[GateFinding] = []
    if used_legacy_payment_block:
        g6_findings.append(
            GateFinding(
                code="LEGACY_NESTED_PAYMENT_HANDLERS",
                severity="medium",
                title="Manifest uses nested ucp.payment.handlers instead of canonical ucp.payment_handlers.",
                remediation="Promote payment handlers to top-level ucp.payment_handlers.",
            )
        )

    raw_handlers_dump = json.dumps(handlers_obj)
    secret_match = _SECRET_LEAK_RE.search(raw_handlers_dump)
    if secret_match:
        leaked_prefix = secret_match.group(0)[:10] + "..."
        g6_findings.append(
            GateFinding(
                code="LEAKED_PSP_SECRET_IN_MANIFEST",
                severity="critical",
                title=f"Private PSP/Shopify secret token ({leaked_prefix}) exposed in public /.well-known/ucp!",
                remediation="Immediately revoke the leaked token and publish only public handler schemas/identifiers.",
            )
        )

    seen_handler_uuids: set[str] = set()
    if not handlers_obj:
        g6_findings.append(
            GateFinding(
                code="MISSING_PAYMENT_HANDLERS",
                severity="critical",
                title="ucp.payment_handlers is missing or empty.",
                remediation="Advertise at least one tokenized payment handler (e.g. com.google.pay, com.stripe.pay, shop.pay).",
            )
        )
    else:
        for h_key, h_list in handlers_obj.items():
            if not isinstance(h_list, list) or len(h_list) == 0:
                g6_findings.append(
                    GateFinding(
                        code="EMPTY_PAYMENT_HANDLER_ARRAY",
                        severity="high",
                        title=f"payment_handlers[{h_key!r}] must be a non-empty array.",
                        remediation=f"Provide a handler descriptor with UUID id, version, spec, and schema for {h_key}.",
                    )
                )
                continue
            for idx, h_desc in enumerate(h_list):
                if not isinstance(h_desc, dict):
                    g6_findings.append(
                        GateFinding(
                            code="MALFORMED_PAYMENT_HANDLER",
                            severity="high",
                            title=f"payment_handlers[{h_key!r}][{idx}] must be an object.",
                            remediation="Provide id, version, spec, and config_schema/schema.",
                        )
                    )
                    continue

                raw_id = str(h_desc.get("id") or "").strip()
                if not raw_id:
                    g6_findings.append(
                        GateFinding(
                            code="MISSING_HANDLER_ID",
                            severity="high",
                            title=f"payment_handlers[{h_key!r}][{idx}] is missing 'id'.",
                            remediation="Assign a deterministic RFC 4122 UUID to each payment handler entry.",
                        )
                    )
                elif not _UUID_RE.match(raw_id):
                    g6_findings.append(
                        GateFinding(
                            code="NON_UUID_HANDLER_ID",
                            severity="medium",
                            title=f"payment_handlers[{h_key!r}][{idx}].id ({raw_id!r}) is not an RFC 4122 UUID.",
                            remediation="Use a standard RFC 4122 UUID (e.g. UUIDv5 derived from merchant domain + handler).",
                        )
                    )
                else:
                    norm_uuid = raw_id.lower()
                    if norm_uuid in seen_handler_uuids:
                        g6_findings.append(
                            GateFinding(
                                code="DUPLICATE_HANDLER_UUID",
                                severity="high",
                                title=f"Duplicate payment handler UUID {norm_uuid} across handlers.",
                                remediation="Assign a distinct UUID per payment handler configuration.",
                            )
                        )
                    seen_handler_uuids.add(norm_uuid)

                hv_ok, _ = _is_valid_calendar_date(h_desc.get("version"))
                if not hv_ok:
                    g6_findings.append(
                        GateFinding(
                            code="INVALID_HANDLER_VERSION",
                            severity="high",
                            title=f"payment_handlers[{h_key!r}][{idx}].version must be YYYY-MM-DD.",
                            remediation=f"Set handler version to \"{root_version or DEFAULT_UCP_VERSION}\".",
                        )
                    )

                sp_info = inspect_https_public_url(h_desc.get("spec"))
                if not sp_info["ok"]:
                    g6_findings.append(
                        GateFinding(
                            code="INVALID_HANDLER_SPEC_URL",
                            severity="high",
                            title=f"payment_handlers[{h_key!r}][{idx}].spec invalid: {sp_info['detail']}",
                            remediation="Provide a public https:// handler specification URL.",
                        )
                    )

                cfg_schema_raw = h_desc.get("config_schema") or h_desc.get("schema")
                cs_info = inspect_https_public_url(cfg_schema_raw)
                if not cs_info["ok"]:
                    g6_findings.append(
                        GateFinding(
                            code="INVALID_HANDLER_SCHEMA_URL",
                            severity="high",
                            title=f"payment_handlers[{h_key!r}][{idx}] schema/config_schema invalid: {cs_info['detail']}",
                            remediation="Provide a public https:// JSON Schema URL for handler configuration.",
                        )
                    )

                inst_schemas = h_desc.get("instrument_schemas")
                if inst_schemas is not None:
                    if not isinstance(inst_schemas, list) or len(inst_schemas) == 0:
                        g6_findings.append(
                            GateFinding(
                                code="EMPTY_INSTRUMENT_SCHEMAS",
                                severity="medium",
                                title=f"payment_handlers[{h_key!r}][{idx}].instrument_schemas is empty.",
                                remediation="Provide at least one https:// payment instrument schema URL.",
                            )
                        )
                    else:
                        for is_url in inst_schemas:
                            is_info = inspect_https_public_url(is_url)
                            if not is_info["ok"]:
                                g6_findings.append(
                                    GateFinding(
                                        code="INVALID_INSTRUMENT_SCHEMA_URL",
                                        severity="high",
                                        title=f"payment_handlers[{h_key!r}][{idx}] instrument_schema invalid: {is_info['detail']}",
                                        remediation="Ensure all instrument_schemas use public https:// URLs.",
                                    )
                                )

    if any(f.severity in ("critical", "high") for f in g6_findings):
        g6_status = "fail"
        g6_summary = "Payment handlers missing, exposing raw secrets, or failing HTTPS schema/version validation."
    elif g6_findings:
        g6_status = "warn"
        g6_summary = "Payment handlers are HTTPS-backed, with UUID format or legacy key warnings."
    else:
        g6_status = "pass"
        g6_summary = f"Verified {len(handlers_obj)} payment handler(s) ({', '.join(handlers_obj.keys())}) with UUIDs and HTTPS schemas."

    gates.append(_make_gate_result(5, g6_status, g6_summary, g6_findings))

    # -------------------------------------------------------------------------
    # UCP-07: Stateless MCP (2026-07-28) / OpenAPI & A2A Dual-Surface Parity
    # -------------------------------------------------------------------------
    g7_findings: list[GateFinding] = []
    mcp_bindings: list[dict[str, Any]] = []
    rest_bindings: list[dict[str, Any]] = []
    if isinstance(shopping_bindings, list):
        for b in shopping_bindings:
            if isinstance(b, dict):
                t = str(b.get("transport") or "").strip().lower()
                if t == "mcp":
                    mcp_bindings.append(b)
                elif t == "rest":
                    rest_bindings.append(b)

    if not mcp_bindings and not rest_bindings:
        g7_findings.append(
            GateFinding(
                code="NO_REST_OR_MCP_SURFACE",
                severity="high",
                title="Neither REST OpenAPI nor Stateless MCP transport surface is available on dev.ucp.shopping.",
                remediation="Expose an HTTPS REST OpenAPI surface and/or Stateless MCP Streamable HTTP (/mcp) surface.",
            )
        )

    for idx, mb in enumerate(mcp_bindings):
        ep_str = str(mb.get("endpoint") or "").strip()
        sc_str = str(mb.get("schema") or "").strip()
        cfg = mb.get("config") if isinstance(mb.get("config"), dict) else {}
        if ep_str.lower().endswith("/sse") or "/sse?" in ep_str.lower():
            g7_findings.append(
                GateFinding(
                    code="DEPRECATED_MCP_SSE_TRANSPORT",
                    severity="high",
                    title=f"MCP binding[{idx}] uses deprecated stateful HTTP+SSE endpoint ({ep_str}).",
                    remediation=f"Migrate to Stateless Streamable HTTP (/mcp) aligned with MCP {MCP_STATELESS_REVISION}.",
                )
            )
        if not sc_str.lower().endswith(".json"):
            g7_findings.append(
                GateFinding(
                    code="MISSING_MCP_OPENRPC_JSON",
                    severity="high",
                    title=f"MCP binding[{idx}] lacks a .json OpenRPC/MCP tool contract schema URL.",
                    remediation="Point MCP schema to https://ucp.dev/2026-01-23/services/shopping/openrpc.json.",
                )
            )
        mcp_rev = str(cfg.get("mcp_protocol_version") or "")
        stateless_flag = cfg.get("stateless_streamable_http")
        if stateless_flag is False:
            g7_findings.append(
                GateFinding(
                    code="STATEFUL_MCP_SESSION_COUPLING",
                    severity="high",
                    title="MCP transport explicitly disables stateless_streamable_http.",
                    remediation=f"Enable stateless Streamable HTTP ({MCP_STATELESS_REVISION}) for horizontally scalable checkout.",
                )
            )
        elif not rest_bindings and mcp_rev < "2026-01-01" and stateless_flag is not True:
            g7_findings.append(
                GateFinding(
                    code="MCP_WITHOUT_OPENAPI_OR_STATELESS_DECLARATION",
                    severity="medium",
                    title="MCP transport is advertised without companion REST OpenAPI binding or explicit 2026-07-28 stateless config.",
                    remediation="Add a companion REST OpenAPI binding or declare config.mcp_protocol_version = '2026-07-28'.",
                )
            )

    for idx, rb in enumerate(rest_bindings):
        sc_str = str(rb.get("schema") or "").strip()
        if sc_str and not sc_str.lower().endswith(".json"):
            g7_findings.append(
                GateFinding(
                    code="NON_JSON_REST_OPENAPI_SCHEMA",
                    severity="medium",
                    title=f"REST binding[{idx}] schema ({sc_str}) does not reference a .json OpenAPI specification.",
                    remediation="Point REST schema to an explicit openapi.json URL.",
                )
            )

    agent_card = bundle.get("agent_card")
    if agent_card is not None:
        if not isinstance(agent_card, dict):
            g7_findings.append(
                GateFinding(
                    code="MALFORMED_A2A_AGENT_CARD",
                    severity="high",
                    title="/.well-known/agent.json must be a JSON object.",
                    remediation="Provide name, url (https://), version, and skills array in /.well-known/agent.json.",
                )
            )
        else:
            ac_url_info = inspect_https_public_url(agent_card.get("url"))
            if not ac_url_info["ok"]:
                g7_findings.append(
                    GateFinding(
                        code="INVALID_A2A_AGENT_URL",
                        severity="high",
                        title=f"/.well-known/agent.json url rejected: {ac_url_info['detail']}",
                        remediation="Serve A2A agent endpoint over public https:// with zero private-IP/localhost targets.",
                    )
                )
            skills = agent_card.get("skills")
            if not isinstance(skills, list) or len(skills) == 0:
                g7_findings.append(
                    GateFinding(
                        code="EMPTY_A2A_SKILLS",
                        severity="medium",
                        title="/.well-known/agent.json declares zero skills.",
                        remediation="Declare commerce skills (e.g. ucp-shopping-checkout) in agent.json skills[].",
                    )
                )

    if any(f.severity in ("critical", "high") for f in g7_findings):
        g7_status = "fail"
        g7_summary = "MCP / OpenAPI / A2A surface failed stateless transport or HTTPS contract validation."
    elif g7_findings:
        g7_status = "warn"
        g7_summary = "Transport surface is reachable, with dual-surface parity or OpenAPI/A2A warnings."
    else:
        surface_labels: list[str] = []
        if rest_bindings:
            surface_labels.append("REST OpenAPI")
        if mcp_bindings:
            surface_labels.append(f"Stateless MCP ({MCP_STATELESS_REVISION})")
        if isinstance(agent_card, dict):
            surface_labels.append("A2A agent.json")
        g7_status = "pass"
        g7_summary = f"Surface parity verified across {' + '.join(surface_labels)}."

    gates.append(_make_gate_result(6, g7_status, g7_summary, g7_findings))

    # -------------------------------------------------------------------------
    # UCP-08: Price/Currency/Inventory Hallucination Guard (Schema.org Parity)
    # -------------------------------------------------------------------------
    g8_findings: list[GateFinding] = []
    checkout_cfg: dict[str, Any] = {}
    fallback_checkout_list = checkout_list if (isinstance(checkout_list, list) and checkout_list) else caps_obj.get("checkout")
    if isinstance(fallback_checkout_list, list) and fallback_checkout_list and isinstance(fallback_checkout_list[0], dict):
        if isinstance(fallback_checkout_list[0].get("config"), dict):
            checkout_cfg = fallback_checkout_list[0]["config"]

    raw_ucp_currencies = checkout_cfg.get("supported_currencies")
    ucp_currencies: list[str] = []
    if isinstance(raw_ucp_currencies, list):
        for c in raw_ucp_currencies:
            code = str(c or "").strip().upper()
            if code not in ISO_4217_CURRENCIES:
                g8_findings.append(
                    GateFinding(
                        code="INVALID_UCP_ISO4217_CURRENCY",
                        severity="high",
                        title=f"Checkout config declares invalid ISO 4217 currency {c!r}.",
                        remediation="Use 3-letter uppercase ISO 4217 codes such as 'USD', 'JPY', or 'EUR'.",
                    )
                )
            elif code not in ucp_currencies:
                ucp_currencies.append(code)

    explicit_offers = bundle.get("schema_org_offers")
    detected_offers: list[dict[str, Any]] = []
    if isinstance(explicit_offers, list):
        for item in explicit_offers:
            if isinstance(item, dict):
                detected_offers.append(
                    {
                        "name": str(item.get("name") or "Product"),
                        "sku": str(item.get("sku") or ""),
                        "price": item.get("price"),
                        "price_currency": str(item.get("price_currency") or item.get("priceCurrency") or "").strip(),
                        "availability": str(item.get("availability") or "").strip(),
                    }
                )
    if isinstance(bundle.get("html"), str) and bundle["html"].strip():
        detected_offers.extend(extract_schema_org_offers_from_html(bundle["html"]))

    for idx, off in enumerate(detected_offers):
        cur = str(off.get("price_currency") or "").strip()
        if not cur or cur != cur.upper() or cur not in ISO_4217_CURRENCIES:
            g8_findings.append(
                GateFinding(
                    code="INVALID_OFFER_CURRENCY",
                    severity="high",
                    title=f"Schema.org Offer[{idx}] has missing or non-ISO-4217 priceCurrency ({cur!r}).",
                    remediation="Set Offer.priceCurrency to an exact ISO 4217 uppercase code matching UCP checkout.",
                )
            )
        elif ucp_currencies and cur not in ucp_currencies:
            g8_findings.append(
                GateFinding(
                    code="OFFER_UCP_CURRENCY_MISMATCH",
                    severity="critical",
                    title=(
                        f"Hallucination trap: Schema.org Offer[{idx}] advertises {cur}, "
                        f"but UCP checkout only accepts {ucp_currencies}."
                    ),
                    remediation=f"Align Offer.priceCurrency ({cur}) with ucp.capabilities['dev.ucp.shopping.checkout'][0].config.supported_currencies.",
                )
            )

        raw_price = off.get("price")
        try:
            num_price = float(str(raw_price).replace(",", "").strip())
            if num_price < 0:
                raise ValueError("negative")
        except (ValueError, TypeError):
            g8_findings.append(
                GateFinding(
                    code="INVALID_OFFER_PRICE",
                    severity="high",
                    title=f"Schema.org Offer[{idx}] has non-numeric or negative price ({raw_price!r}).",
                    remediation="Format Offer.price as a non-negative decimal string (e.g. '34.00' or '4800').",
                )
            )

        avail = str(off.get("availability") or "").strip()
        avail_slug = avail.rsplit("/", 1)[-1].lower() if avail else ""
        if avail_slug not in _VALID_SCHEMA_AVAILABILITIES:
            g8_findings.append(
                GateFinding(
                    code="MISSING_OFFER_AVAILABILITY",
                    severity="medium",
                    title=f"Schema.org Offer[{idx}] omits standard availability URI (got {avail!r}).",
                    remediation="Include \"availability\": \"https://schema.org/InStock\" (or OutOfStock/PreOrder) to prevent stock hallucination.",
                )
            )

    if not detected_offers and not ucp_currencies:
        if not checkout_list:
            g8_findings.append(
                GateFinding(
                    code="NO_CHECKOUT_CURRENCY_CONTRACT",
                    severity="high",
                    title="No checkout capability or Schema.org Offer currency metadata available.",
                    remediation="Declare dev.ucp.shopping.checkout with ISO 4217 supported_currencies and matching Schema.org Offer JSON-LD.",
                )
            )
        else:
            g8_findings.append(
                GateFinding(
                    code="IMPLICIT_CHECKOUT_CURRENCY",
                    severity="medium",
                    title="Neither Schema.org Offer nor checkout config.supported_currencies specifies ISO 4217 currencies.",
                    remediation="Add config.supported_currencies (e.g. ['USD']) on dev.ucp.shopping.checkout to prevent agent FX guessing.",
                )
            )

    if any(f.severity in ("critical", "high") for f in g8_findings):
        g8_status = "fail"
        g8_summary = "Price/currency mismatch or invalid Schema.org Offer detected (agentic checkout hallucination risk)."
    elif g8_findings:
        g8_status = "warn"
        g8_summary = "No currency conflict found, but explicit ISO 4217 currency or availability metadata is incomplete."
    else:
        cur_summary = ", ".join(ucp_currencies) if ucp_currencies else detected_offers[0]["price_currency"]
        g8_status = "pass"
        g8_summary = (
            f"ISO 4217 currency ({cur_summary}) and inventory parity verified "
            f"({len(detected_offers)} Offer(s) cross-checked)."
        )

    gates.append(_make_gate_result(7, g8_status, g8_summary, g8_findings))

    # -------------------------------------------------------------------------
    # UCP-09: AP2 Mandate & Idempotency / Replay Protection Readiness
    # -------------------------------------------------------------------------
    g9_findings: list[GateFinding] = []
    ap2_list = caps_obj.get("dev.ucp.shopping.ap2_mandate")
    has_ap2_cap = isinstance(ap2_list, list) and len(ap2_list) > 0
    ap2_cfg: dict[str, Any] = {}
    if has_ap2_cap and isinstance(ap2_list[0], dict) and isinstance(ap2_list[0].get("config"), dict):
        ap2_cfg = ap2_list[0]["config"]

    if checkout_cfg.get("allow_unverified_agent_autocharge") is True:
        g9_findings.append(
            GateFinding(
                code="UNVERIFIED_AGENT_AUTOCHARGE_ENABLED",
                severity="critical",
                title="Checkout explicitly permits unverified autonomous agent auto-charging without AP2 mandate!",
                remediation="Remove allow_unverified_agent_autocharge and require cryptographic AP2 CheckoutMandate / PaymentMandate.",
            )
        )

    if checkout_cfg.get("idempotency_key_required") is False:
        g9_findings.append(
            GateFinding(
                code="IDEMPOTENCY_PROTECTION_DISABLED",
                severity="critical",
                title="Checkout explicitly disables Idempotency-Key deduplication (severe agent double-charge risk).",
                remediation="Require Idempotency-Key on REST complete_checkout and meta['idempotency-key'] on MCP tool calls.",
            )
        )

    if checkout_cfg.get("ap2_mandate_required") is False or ap2_cfg.get("require_user_signature") is False:
        g9_findings.append(
            GateFinding(
                code="AP2_USER_SIGNATURE_DISABLED",
                severity="high",
                title="AP2 user mandate signature verification is explicitly disabled.",
                remediation="Enforce ap2_mandate_required = true and require_user_signature = true.",
            )
        )

    if not g9_findings:
        if not checkout_list:
            g9_findings.append(
                GateFinding(
                    code="NO_CHECKOUT_FOR_AP2_MANDATE",
                    severity="high",
                    title="Cannot enforce AP2 mandates or idempotency without dev.ucp.shopping.checkout.",
                    remediation="Declare dev.ucp.shopping.checkout + dev.ucp.shopping.ap2_mandate.",
                )
            )
        else:
            has_explicit_idempotency = checkout_cfg.get("idempotency_key_required") is True
            has_ap2_guard = has_ap2_cap or checkout_cfg.get("ap2_mandate_required") is True
            if not has_ap2_guard:
                g9_findings.append(
                    GateFinding(
                        code="MISSING_AP2_MANDATE_CAPABILITY",
                        severity="medium",
                        title="No dev.ucp.shopping.ap2_mandate extension or ap2_mandate_required guardrail advertised.",
                        remediation="Add dev.ucp.shopping.ap2_mandate (extending checkout) to verify cryptographic CheckoutMandate & SD-JWT-VC.",
                    )
                )
            if not has_explicit_idempotency and not has_ap2_cap:
                g9_findings.append(
                    GateFinding(
                        code="UNSPECIFIED_IDEMPOTENCY_POLICY",
                        severity="medium",
                        title="Checkout omits explicit idempotency-key replay protection metadata.",
                        remediation="Set config.idempotency_key_required = true (and MCP meta['idempotency-key']) to prevent retry double-charges.",
                    )
                )

    if any(f.severity in ("critical", "high") for f in g9_findings):
        g9_status = "fail"
        g9_summary = "AP2 payment mandate or idempotency protection is disabled or missing core checkout."
    elif g9_findings:
        g9_status = "warn"
        g9_summary = "Checkout exists, but explicit AP2 mandate capability or idempotency replay policy should be added."
    else:
        g9_status = "pass"
        g9_summary = "AP2 cryptographic mandate verification and idempotency-key replay protection verified."

    gates.append(_make_gate_result(8, g9_status, g9_summary, g9_findings))

    # -------------------------------------------------------------------------
    # UCP-10: Edge Discovery Headers & 1-Click /.well-known/ucp Bundle
    # -------------------------------------------------------------------------
    g10_findings: list[GateFinding] = []
    raw_headers = bundle.get("http_headers")
    norm_headers: dict[str, str] = {}
    if isinstance(raw_headers, dict):
        norm_headers = {str(k).strip().lower(): str(v).strip() for k, v in raw_headers.items()}

    status_code = bundle.get("status_code")
    if status_code is not None and int(status_code) != 200:
        g10_findings.append(
            GateFinding(
                code="NON_200_DISCOVERY_STATUS",
                severity="critical",
                title=f"/.well-known/ucp returned HTTP {status_code} instead of 200 OK.",
                remediation="Serve /.well-known/ucp directly with HTTP 200 over HTTPS.",
            )
        )

    if norm_headers:
        ctype = norm_headers.get("content-type", "").lower()
        if "application/json" not in ctype:
            g10_findings.append(
                GateFinding(
                    code="INVALID_DISCOVERY_CONTENT_TYPE",
                    severity="critical",
                    title=f"/.well-known/ucp served with Content-Type {ctype!r} instead of application/json.",
                    remediation="Configure edge route to return Content-Type: application/json; charset=utf-8 (prevent SPA HTML soft-404s).",
                )
            )
        acao = norm_headers.get("access-control-allow-origin", "")
        if not acao:
            g10_findings.append(
                GateFinding(
                    code="MISSING_CORS_HEADER",
                    severity="medium",
                    title="Response headers omit Access-Control-Allow-Origin: * for cross-origin agent discovery.",
                    remediation="Add Access-Control-Allow-Origin: * on /.well-known/ucp and /.well-known/agent.json.",
                )
            )
        cc = norm_headers.get("cache-control", "")
        if not cc:
            g10_findings.append(
                GateFinding(
                    code="MISSING_CACHE_CONTROL_HEADER",
                    severity="medium",
                    title="Response headers omit Cache-Control policy on /.well-known/ucp.",
                    remediation="Add Cache-Control: public, max-age=3600, stale-while-revalidate=86400.",
                )
            )

    if not isinstance(ucp_obj, dict) or not services_obj or not caps_obj:
        g10_findings.append(
            GateFinding(
                code="MANIFEST_NOT_DEPLOY_READY",
                severity="high",
                title="Manifest cannot be deployed cleanly until core ucp envelope, services, and capabilities are present.",
                remediation="Use the generated 1-Click /.well-known/ucp Manifest + Cloudflare Worker / Nginx bundle below.",
            )
        )

    # Synthesize 1-Click Deployment & Remediation Bundle for this merchant
    gen_caps = [
        k
        for k in caps_obj
        if k in OFFICIAL_UCP_CAPABILITIES
    ] or None
    gen_handlers = [
        k
        for k in handlers_obj
        if k == "shop.pay" or _HANDLER_NS_RE.match(k)
    ] or None
    gen_currencies = ucp_currencies or (
        [
            str(o["price_currency"]).upper()
            for o in detected_offers
            if str(o.get("price_currency") or "").upper() in ISO_4217_CURRENCIES
        ]
        or ["USD"]
    )
    try:
        safe_platform = inferred_platform if inferred_platform in ("shopify", "custom_rest", "stateless_mcp") else "shopify"
        deployment_bundle = generate_ucp_bundle(
            inferred_domain,
            platform=safe_platform,
            capabilities=gen_caps,
            payment_handlers=gen_handlers,
            currencies=gen_currencies,
            version=root_version if (root_version and root_version >= "2026-01-01") else DEFAULT_UCP_VERSION,
            include_a2a_agent_card=True,
        )
    except ValueError:
        deployment_bundle = generate_ucp_bundle("nordic-roast.shop", platform="shopify")

    if any(f.severity in ("critical", "high") for f in g10_findings):
        g10_status = "fail"
        g10_summary = "Discovery endpoint returned non-200 / non-JSON response or manifest envelope is incomplete."
    elif g10_findings:
        g10_status = "warn"
        g10_summary = "JSON discovery payload parses, but CORS or Cache-Control edge headers are missing."
    else:
        g10_status = "pass"
        g10_summary = "Edge delivery contract verified and 1-Click Cloudflare Worker + Nginx bundle generated."

    gates.append(_make_gate_result(9, g10_status, g10_summary, g10_findings))

    score = sum(g.earned_points for g in gates)
    gates_passed = sum(1 for g in gates if g.status == "pass")
    gates_warned = sum(1 for g in gates if g.status == "warn")
    gates_failed = sum(1 for g in gates if g.status == "fail")
    findings_count = sum(len(g.findings) for g in gates)

    if gates_failed == 0 and gates_warned == 0:
        overall_status = "compliant"
    elif gates_failed == 0:
        overall_status = "action_required"
    else:
        overall_status = "non_compliant"

    surfaces = {
        "has_ucp_manifest": isinstance(ucp_obj, dict),
        "transports": valid_transports_found,
        "capabilities_count": len(caps_obj),
        "payment_handlers_count": len(handlers_obj),
        "has_a2a_agent_card": isinstance(agent_card, dict),
        "has_llms_txt": bool(isinstance(bundle.get("llms_txt"), str) and bundle["llms_txt"].strip()),
        "offers_count": len(detected_offers),
    }

    return UcpAuditReport(
        domain=inferred_domain,
        ucp_version=root_version,
        status=overall_status,
        score=score,
        grade=_letter_grade(score),
        gates_passed=gates_passed,
        gates_warned=gates_warned,
        gates_failed=gates_failed,
        findings_count=findings_count,
        gates=gates,
        dag=dag_info,
        detected_offers=detected_offers,
        surfaces=surfaces,
        deployment_bundle=deployment_bundle,
    )


def build_sample_presets() -> dict[str, dict[str, Any]]:
    """Build 3 realistic UCP audit presets for CLI, test suite, and web workbench."""
    prod_bundle = generate_ucp_bundle(
        "nordic-roast.shop",
        platform="shopify",
        capabilities=[
            "dev.ucp.shopping.checkout",
            "dev.ucp.shopping.fulfillment",
            "dev.ucp.shopping.discount",
            "dev.ucp.shopping.order",
            "dev.ucp.shopping.ap2_mandate",
        ],
        payment_handlers=["com.google.pay", "com.stripe.pay", "shop.pay"],
        currencies=["USD"],
        version=DEFAULT_UCP_VERSION,
        include_a2a_agent_card=True,
        store_name="Nordic Roast Coffee",
    )

    return {
        "broken-shopify-draft": {
            "domain": "kuroshio-craft.jp",
            "platform": "shopify",
            "status_code": 200,
            "http_headers": {
                "Content-Type": "text/html; charset=utf-8",
            },
            "manifest": {
                "ucp": {
                    "version": "1.0",
                    "services": {
                        "dev.ucp.shopping": [
                            {
                                "version": "1.0",
                                "transport": "rest",
                                "endpoint": "https://kuroshio-craft.jp/api/ucp",
                                "schema": "https://ucp.dev/2026-01-23/services/shopping/openapi.json",
                            }
                        ]
                    },
                    "capabilities": {
                        "checkout": [
                            {
                                "version": "1.0",
                                "spec": "https://ucp.dev/specification/checkout",
                                "schema": "https://ucp.dev/2026-01-23/schemas/shopping/checkout.json",
                                "config": {
                                    "supported_currencies": ["USD"],
                                },
                            }
                        ],
                        "dev.ucp.shopping.discount": [
                            {
                                "version": "2026-01-23",
                                "spec": "https://ucp.dev/specification/discount",
                                "schema": "https://ucp.dev/2026-01-23/schemas/shopping/discount.json",
                                "extends": "dev.ucp.shopping.checkout",
                            }
                        ],
                    },
                    "payment_handlers": {
                        "shop.pay": [
                            {
                                "id": "shop_pay_draft_01",
                                "version": "2026-01-23",
                                "spec": "https://shopify.dev/docs/agents/ucp/shop-pay",
                                "schema": "https://shopify.dev/ucp/2026-01-23/schemas/shop_pay_config.json",
                                "config": {
                                    "admin_token": "shpat_4f9c2a8b1e7d001122334455",
                                },
                            }
                        ]
                    },
                }
            },
            "schema_org_offers": [
                {
                    "name": "Indigo Dyed Linen Apron",
                    "sku": "KC-APRON-04",
                    "price": "12800",
                    "priceCurrency": "JPY",
                    "availability": "https://schema.org/InStock",
                }
            ],
        },
        "cyclic-http-ssrf": {
            "domain": "atelier-verre.eu",
            "platform": "stateless_mcp",
            "status_code": 200,
            "http_headers": {
                "Content-Type": "application/json",
            },
            "manifest": {
                "ucp": {
                    "version": "2026-01-23",
                    "services": {
                        "dev.ucp.shopping": [
                            {
                                "version": "2026-01-23",
                                "spec": "https://ucp.dev/specification/overview",
                                "transport": "rest",
                                "endpoint": "http://api.atelier-verre.eu/ucp/v1",
                                "schema": "https://ucp.dev/2026-01-23/services/shopping/openapi.json",
                            },
                            {
                                "version": "2026-01-23",
                                "spec": "https://ucp.dev/specification/overview",
                                "transport": "rest",
                                "endpoint": "https://10.0.4.22:8443/ucp/internal",
                                "schema": "https://ucp.dev/2026-01-23/services/shopping/openapi.json",
                            },
                            {
                                "version": "2026-01-23",
                                "spec": "https://ucp.dev/specification/mcp",
                                "transport": "mcp",
                                "endpoint": "https://atelier-verre.eu/ucp/sse",
                                "schema": "https://atelier-verre.eu/ucp/mcp-docs",
                            },
                        ]
                    },
                    "capabilities": {
                        "dev.ucp.shopping.checkout": [
                            {
                                "version": "2026-01-23",
                                "spec": "https://ucp.dev/specification/checkout",
                                "schema": "https://ucp.dev/2026-01-23/schemas/shopping/checkout.json",
                                "config": {
                                    "supported_currencies": ["EUR"],
                                    "idempotency_key_required": False,
                                },
                            }
                        ],
                        "dev.ucp.shopping.fulfillment": [
                            {
                                "version": "2026-01-23",
                                "spec": "https://ucp.dev/specification/fulfillment",
                                "schema": "https://ucp.dev/2026-01-23/schemas/shopping/fulfillment.json",
                                "extends": "dev.ucp.shopping.discount",
                            }
                        ],
                        "dev.ucp.shopping.discount": [
                            {
                                "version": "2026-01-23",
                                "spec": "https://ucp.dev/specification/discount",
                                "schema": "https://ucp.dev/2026-01-23/schemas/shopping/discount.json",
                                "extends": "dev.ucp.shopping.fulfillment",
                            }
                        ],
                        "dev.ucp.shopping.custom_vip": [
                            {
                                "version": "2026-01-23",
                                "spec": "https://atelier-verre.eu/ucp/vip",
                                "schema": "https://atelier-verre.eu/ucp/vip.json",
                            }
                        ],
                    },
                    "payment_handlers": {
                        "com.stripe.pay": [
                            {
                                "id": "8c9202bd-63cc-4241-8d24-d57ce69ea31c",
                                "version": "2026-01-23",
                                "spec": "https://docs.stripe.com/agentic-commerce/ucp/2026-01-23",
                                "schema": "http://127.0.0.1:9001/stripe-config.json",
                            }
                        ]
                    },
                }
            },
            "agent_card": {
                "name": "Atelier Verre Internal Agent",
                "url": "http://localhost:9000/a2a",
                "version": "0.1.0",
                "skills": [],
            },
            "schema_org_offers": [
                {
                    "name": "Hand-Blown Carafe 750ml",
                    "sku": "AV-CARAFE-750",
                    "price": "86.00",
                    "priceCurrency": "EUR",
                    "availability": "https://schema.org/InStock",
                }
            ],
        },
        "production-google-stripe-ucp": {
            "domain": "nordic-roast.shop",
            "platform": "shopify",
            "status_code": 200,
            "http_headers": prod_bundle["http_headers"],
            "manifest": prod_bundle["manifest"],
            "agent_card": prod_bundle["agent_card"],
            "llms_txt": "# Nordic Roast Coffee\n> Specialty coffee roaster supporting UCP 2026-01-23 & AP2 mandates.\n",
            "schema_org_offers": [
                {
                    "name": "Nordic Roast Flagship Single Origin 250g",
                    "sku": "UCP-SKU-101",
                    "price": "34.00",
                    "priceCurrency": "USD",
                    "availability": "https://schema.org/InStock",
                }
            ],
        },
    }
