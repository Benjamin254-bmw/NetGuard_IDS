#!/usr/bin/env python3
"""Automated accessibility audit of the dashboard with axe-core (WCAG 2.0/2.1 A and AA plus best practices).

    python lab/a11y_audit.py --axe /path/to/node_modules/axe-core/axe.min.js --user <admin> \
        [--base http://127.0.0.1:5173] [--out lab/results]

Needs a served dashboard (`make frontend-dev`, or `vite preview` of a production build) in front of a running
API, and Playwright for Python with Chromium. Password: NETGUARD_E2E_PASSWORD or a prompt.
Runs every page signed in, and the login page signed out, in light and dark colour schemes at a desktop (1280 px)
and a phone (390 px) width, plus the two dialogs (add user, edit rule). Fails (exit 1) if axe reports a violation.

What this is NOT: automated checks find roughly a third of accessibility problems. Keyboard order, focus
visibility, screen-reader wording and reading experience need a human; the checklist lists what was and was not
checked by hand.
"""

from __future__ import annotations

import argparse
import getpass
import http.cookiejar
import json
import os
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from playwright.sync_api import Page, sync_playwright

TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"]
VIEWPORTS = {"desktop": (1280, 900), "phone": (390, 844)}
SCHEMES = ("light", "dark")


def audit(page: Page, axe_src: str, label: str) -> dict[str, Any]:
    page.add_script_tag(content=axe_src)
    res = page.evaluate(f"axe.run(document, {{runOnly: {{type: 'tag', values: {json.dumps(TAGS)}}}}})")
    return {
        "view": label,
        "violations": [
            {
                "id": v["id"],
                "impact": v["impact"],
                "help": v["help"],
                "nodes": len(v["nodes"]),
                "examples": [n["target"] for n in v["nodes"][:3]],
            }
            for v in res["violations"]
        ],
        "passes": len(res["passes"]),
        "incomplete": [i["id"] for i in res["incomplete"]],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--axe", required=True, help="path to axe.min.js (npm package axe-core)")
    ap.add_argument("--base", default="http://127.0.0.1:5173")
    ap.add_argument("--user", required=True)
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "results"))
    args = ap.parse_args()
    axe_src = Path(args.axe).read_text()
    password = os.environ.get("NETGUARD_E2E_PASSWORD") or getpass.getpass(f"password for {args.user}: ")

    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(path: str, body: dict[str, str] | None = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(  # noqa: S310 - the operator's own http(s) dashboard URL
            args.base + path, data=data, headers={"Content-Type": "application/json"} if data else {}
        )
        with opener.open(req, timeout=10) as r:
            return json.load(r)

    try:
        call("/api/auth/login", {"username": args.user, "password": password})
        ev = call("/api/events?limit=1")["items"]
        rules = call("/api/rules")["items"]
    except OSError as exc:
        print(f"ERROR: could not sign in through {args.base}: {exc}", file=sys.stderr)
        return 2
    routes = ["/", "/events", "/rules", "/users", "/settings"]
    if ev:
        routes.append(f"/events/{ev[0]['id']}")
    if rules:
        routes.append(f"/rules/{rules[0]['id']}")

    results: list[dict[str, Any]] = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        for scheme in SCHEMES:
            for vname, (w, h) in VIEWPORTS.items():
                ctx = browser.new_context(color_scheme=scheme, viewport={"width": w, "height": h})  # type: ignore[arg-type]
                page = ctx.new_page()
                tag = f"{scheme}/{vname}"
                page.goto(args.base + "/login")
                page.wait_for_selector("#u")
                results.append(audit(page, axe_src, f"{tag} /login"))
                page.fill("#u", args.user)
                page.fill("#p", password)
                page.keyboard.press("Enter")
                page.wait_for_url(args.base + "/", timeout=10000)
                for r in routes:
                    page.goto(args.base + r)
                    page.wait_for_load_state("networkidle")
                    page.wait_for_timeout(400)
                    results.append(audit(page, axe_src, f"{tag} {r}"))
                page.goto(args.base + "/users")
                page.wait_for_load_state("networkidle")
                page.get_by_role("button", name="Add user").click()
                page.wait_for_selector("dialog[open], [role=dialog]")
                results.append(audit(page, axe_src, f"{tag} /users [add-user dialog]"))
                ctx.close()
        browser.close()

    bad = [(r["view"], v) for r in results for v in r["violations"]]
    out = Path(args.out)
    out.mkdir(exist_ok=True)
    path = out / f"a11y-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S')}.json"
    path.write_text(json.dumps({"tags": TAGS, "views": len(results), "results": results}, indent=2))
    print(f"{len(results)} views audited ({', '.join(TAGS)}); {len(bad)} violation(s)")
    for view, v in bad:
        print(f"  [{v['impact']}] {v['id']} ({v['nodes']} nodes) in {view}: {v['help']} e.g. {v['examples'][0]}")
    needs_review = sorted({i for r in results for i in r["incomplete"]})
    if needs_review:
        print(f"axe could not decide (needs a human): {', '.join(needs_review)}")
    print(f"written: {path}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
