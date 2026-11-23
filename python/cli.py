"""Zero-dependency CLI for UCPGATE (`ucp-agentic-commerce-auditor`)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from .auditor import (
    UcpParseError,
    audit_ucp_readiness,
    audit_ucp_text,
    build_sample_presets,
)
from .generator import (
    DEFAULT_UCP_VERSION,
    generate_ucp_bundle,
)


def _format_text_report(rep: dict) -> str:
    lines: list[str] = []
    ver_str = rep.get("ucp_version") or "missing"
    lines.append(f"UCPGATE Audit Report · UCP Version: {ver_str} · Store: {rep['domain']}")
    lines.append(
        f"Status: {rep['status'].upper()} | Score: {rep['score']}/100 (Grade {rep['grade']})"
    )
    lines.append(
        f"Gates: {rep['gates_passed']} PASS / {rep['gates_warned']} WARN / "
        f"{rep['gates_failed']} FAIL | Findings: {rep['findings_count']}"
    )
    dag = rep.get("dag") or {}
    lines.append(
        f"Capability DAG: {len(dag.get('nodes') or [])} node(s), {len(dag.get('edges') or [])} edge(s), "
        f"acyclic={dag.get('is_acyclic')}"
    )
    lines.append("-" * 88)
    for g in rep["gates"]:
        badge = str(g["status"]).upper().ljust(4)
        lines.append(f"[{badge}] {g['gate_id']} ({g['weight']}pt) {g['title']}")
        lines.append(f"       {g['summary']}")
        for f in g.get("findings") or []:
            lines.append(f"       -> ({f['severity']}) [{f['code']}] {f['title']}")
            lines.append(f"          Fix: {f['remediation']}")
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    presets = sorted(build_sample_presets().keys())
    parser = argparse.ArgumentParser(
        prog="ucpgate",
        description=(
            "Audit /.well-known/ucp + AP2 + /.well-known/agent.json across 10 Agentic Commerce gates "
            "or generate production 1-click UCP manifests + Cloudflare Worker / Nginx edge configs."
        ),
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Path to a /.well-known/ucp JSON/JSONC file or composite audit bundle.",
    )
    parser.add_argument(
        "--preset",
        choices=presets,
        help="Run one of the built-in UCP reference presets.",
    )
    parser.add_argument(
        "--agent-card",
        help="Optional path to a companion /.well-known/agent.json A2A Agent Card.",
    )
    parser.add_argument(
        "--html",
        help="Optional path to a storefront product HTML page with Schema.org Offer JSON-LD.",
    )
    parser.add_argument(
        "--generate",
        action="store_true",
        help="Run 1-Click /.well-known/ucp + A2A + Edge Bundle Generator instead of auditing.",
    )
    parser.add_argument(
        "--domain",
        default="nordic-roast.shop",
        help="Merchant public domain for --generate (default: nordic-roast.shop).",
    )
    parser.add_argument(
        "--platform",
        default="shopify",
        help="Merchant platform for --generate: shopify, custom_rest, or stateless_mcp.",
    )
    parser.add_argument(
        "--capabilities",
        help="Comma-separated capabilities for --generate (e.g. checkout,fulfillment,discount,order,ap2_mandate).",
    )
    parser.add_argument(
        "--handlers",
        help="Comma-separated payment handlers for --generate (e.g. com.google.pay,com.stripe.pay,shop.pay).",
    )
    parser.add_argument(
        "--currencies",
        default="USD",
        help="Comma-separated ISO 4217 currencies for --generate (default: USD).",
    )
    parser.add_argument(
        "--ucp-version",
        default=DEFAULT_UCP_VERSION,
        help=f"UCP YYYY-MM-DD version for --generate (default: {DEFAULT_UCP_VERSION}).",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--export-bundle",
        help="Write the 1-Click deployment bundle JSON (manifest, agent_card, Cloudflare Worker, Nginx) to disk.",
    )
    parser.add_argument(
        "--fail-on",
        choices=("fail", "warn", "none"),
        default="fail",
        help="Exit with code 2 when gates fail ('fail') or warn/fail ('warn').",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.generate:
        caps = [x.strip() for x in args.capabilities.split(",") if x.strip()] if args.capabilities else None
        handlers = [x.strip() for x in args.handlers.split(",") if x.strip()] if args.handlers else None
        currencies = [x.strip() for x in args.currencies.split(",") if x.strip()] if args.currencies else ["USD"]
        try:
            bundle = generate_ucp_bundle(
                args.domain,
                platform=args.platform,
                capabilities=caps,
                payment_handlers=handlers,
                currencies=currencies,
                version=args.ucp_version,
                include_a2a_agent_card=True,
            )
        except ValueError as exc:
            print(f"Generator error: {exc}", file=sys.stderr)
            return 1

        if args.export_bundle:
            out_p = Path(args.export_bundle)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(json.dumps(bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        if args.format == "json":
            print(json.dumps(bundle, indent=2, ensure_ascii=False))
        else:
            print(json.dumps(bundle["manifest"], indent=2, ensure_ascii=False))
        return 0

    if not args.target and not args.preset:
        parser.error("Provide a target /.well-known/ucp file, --preset <name>, or --generate.")

    try:
        if args.preset:
            presets = build_sample_presets()
            report = audit_ucp_readiness(presets[args.preset])
        else:
            target_path = Path(str(args.target))
            if not target_path.is_file():
                print(f"Error: target file not found: {target_path}", file=sys.stderr)
                return 1
            raw_text = target_path.read_text(encoding="utf-8")
            if args.agent_card or args.html:
                from .auditor import strip_jsonc_comments

                base_doc = json.loads(strip_jsonc_comments(raw_text))
                composite: dict = (
                    dict(base_doc)
                    if ("manifest" in base_doc and isinstance(base_doc["manifest"], dict))
                    else {"manifest": base_doc}
                )
                if args.agent_card:
                    ac_path = Path(args.agent_card)
                    if not ac_path.is_file():
                        print(f"Error: agent card file not found: {ac_path}", file=sys.stderr)
                        return 1
                    composite["agent_card"] = json.loads(strip_jsonc_comments(ac_path.read_text(encoding="utf-8")))
                if args.html:
                    html_path = Path(args.html)
                    if not html_path.is_file():
                        print(f"Error: HTML file not found: {html_path}", file=sys.stderr)
                        return 1
                    composite["html"] = html_path.read_text(encoding="utf-8")
                report = audit_ucp_readiness(composite)
            else:
                report = audit_ucp_text(raw_text)
    except (UcpParseError, json.JSONDecodeError) as exc:
        print(f"Parse error: {exc}", file=sys.stderr)
        return 1

    rep_dict = report.to_dict()

    if args.export_bundle:
        out_b = Path(args.export_bundle)
        out_b.parent.mkdir(parents=True, exist_ok=True)
        out_b.write_text(
            json.dumps(rep_dict["deployment_bundle"], indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    if args.format == "json":
        print(json.dumps(rep_dict, indent=2, ensure_ascii=False))
    else:
        print(_format_text_report(rep_dict))

    if args.fail_on == "fail" and rep_dict["gates_failed"] > 0:
        return 2
    if args.fail_on == "warn" and (rep_dict["gates_failed"] > 0 or rep_dict["gates_warned"] > 0):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
